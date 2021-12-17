package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/tralahm/drcmpesaproxy/docs"
	"github.com/tralahm/vodacomgo"
)

var (
	ServPort       = getEnv("PORT", "8000")
	c2bCallbackUrl = getEnv("CLIENT_C2B_CALLBACK_URL", "https://c2b_vodacash/")
	b2cCallbackUrl = getEnv("CLIENT_B2C_CALLBACK_URL", "https://b2c_vodacash/")
	redisUrl       = getEnv("REDIS_URL", "localhost:6379")
	internalC2B    = "https://ipg.betmondenge.com/api/v1/c2b_callback"
	internalB2C    = "https://ipg.betmondenge.com/api/v1/b2c_callback"
)

func init() {
}

// @title DRC MPESA Proxy REST API
// @version 1.0
// @description This is a service for interacting with Vodacom's DRC MPESA SOAP Integrated Payment Gateway.
// @termsOfService https://blog.tralahm.com
// @contact.name API Support
// @contact.email briantralah@gmail.com
// @license.name GNU GENERAL PUBLIC LICENSE
// @license.url http://www.gnu.org/licenses/
// @host ipg.betmondenge.com
// @BasePath /
func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://*", "*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Forwarded-IP",
			"X-Client-C2BCallbackURL",
			"X-Client-B2CCallbackURL",
			"X-Client-ThirdPartyReference",
			"Environment",
		},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	handler := NewIpgHandler()
	r.Get("/api/v1/health", handler.Health)
	r.Get("/swagger.json", handler.Swagger)
	r.Get("/api/v1/ready", handler.Ready)
	r.Post("/api/v1/login", handler.LoginV1)
	r.Post("/api/v2/login", handler.Login)
	r.Post("/api/v1/c2b", handler.C2B)
	r.Post("/api/v1/b2c", handler.B2C)
	r.Post("/api/v1/vodacash_c2b_callback", handler.C2BCallback)
	r.Post("/api/v1/vodacash_b2c_callback", handler.B2CCallback)
	r.Post("/api/v1/c2b_callback", handler.C2BCallback)
	r.Post("/api/v1/b2c_callback", handler.B2CCallback)
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("https://raw.githubusercontent.com/tralahm/drcmpesaproxy/master/docs/swagger.json"))) // url pointing to api definition

	handler.logger.Printf("Server starting on 0.0.0.0:%s\n", ServPort)

	err := http.ListenAndServe("0.0.0.0:"+ServPort, r)
	if err != nil {
		handler.logger.Fatal(err)
	}

}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

type Client interface {
	Do(*http.Request) (*http.Response, error)
}
type ClientFunc func(*http.Request) (*http.Response, error)

func (f ClientFunc) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

type Decorator func(Client) Client

func Decorate(c Client, ds ...Decorator) Client {
	decorated := c
	for _, decorate := range ds {
		decorated = decorate(decorated)
	}
	return decorated
}

func Header(name, value string) Decorator {
	return func(c Client) Client {
		return ClientFunc(func(r *http.Request) (*http.Response, error) {
			r.Header.Add(name, value)
			return c.Do(r)
		})
	}
}

type IpgHandler struct {
	Username string
	Password string
	Token    string
	client   Client
	logger   *log.Logger
	sandbox  bool
	DB       *Database
}

func NewIpgHandler() *IpgHandler {
	logger := log.New(os.Stdout, "drcmpesaproxy: ", log.Ldate|log.Ltime|log.Lshortfile)
	DB, err := NewDatabase(redisUrl, "bmb@2021")
	if err != nil {
		log.Fatalln(err)
		panic(err)
	}
	DB.Set("CLIENT_C2B_CALLBACK_URL", "https://c2b_vodacash/")
	DB.Set("CLIENT_B2C_CALLBACK_URL", "https://b2c_vodacash/")
	hs := &IpgHandler{
		client: Decorate(http.DefaultClient,
			Header("Accept", "application/xml,text/xml"),
			Header("Content-Type", "application/xml"),
		),
		logger:  logger,
		sandbox: false,
		DB:      DB,
	}
	return hs
}
func (ipg *IpgHandler) getIpgUrl(sandbox bool) string {
	if sandbox {
		return "https://uatipg.m-pesa.vodacom.cd"
	}
	return "https://ipg.m-pesa.vodacom.cd"
}

func (ipg *IpgHandler) setEnv(req *http.Request) {
	env := req.Header.Get("Environment")
	if env == "" || env == "live" || env == "production" {
		ipg.sandbox = false
	} else {
		ipg.sandbox = true
	}
}

// GetSwagger godoc
// @Summary Get API Swagger Definition
// @Tags internal
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /swagger.json [get]
func (ipg *IpgHandler) Swagger(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, req, "docs/swagger.json")
}

// GetHealth godoc
// @Summary Check Health Status
// @Tags internal
// @Accept json
// @Produce json
// @Success 200 {object} Status
// @Router /api/v1/health [get]
func (ipg *IpgHandler) Health(w http.ResponseWriter, req *http.Request) {
	ipg.respondJSON(w, 200, map[string]string{"status": "healthy"})
}

// GetReady godoc
// @Summary Check Readiness Status
// @Tags internal
// @Accept json
// @Produce json
// @Success 200 {object} Status
// @Router /api/v1/ready [get]
func (ipg *IpgHandler) Ready(w http.ResponseWriter, req *http.Request) {
	ipg.respondJSON(w, 200, map[string]string{"status": "ready", "c2b": c2bCallbackUrl, "b2c": b2cCallbackUrl})
}

// Login godoc
// @Summary Authenticate against the Remote IPG
// @Description Login to the MPESA Ipg with the credentials and return JSON response.
// @Tags login
// @Accept json
// @Produce json
// @Param credentials body Login true "Login"
// @Success 201 {object} LoginResponse2
// @Router /api/v1/login [post]
func (ipg *IpgHandler) LoginV1(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	var login vodacomgo.Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	ipg.setEnv(req)
	loginresponse, err := ipg.ipgLogin(login)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	v1response := map[string]string{}
	v1response["code"] = loginresponse.Code
	v1response["description"] = loginresponse.Description
	v1response["detail"] = loginresponse.Detail
	v1response["transactionID"] = loginresponse.TransactionID
	v1response["event_id"] = loginresponse.EventID
	v1response["token"] = loginresponse.SessionID
	ipg.respondJSON(w, http.StatusCreated, v1response)
}

// Login godoc
// @Summary Authenticate against the Remote IPG
// @Description Login to the MPESA Ipg with the credentials and return JSON response.
// @Tags login
// @Accept json
// @Produce json
// @Param credentials body Login true "Login"
// @Success 201 {object} LoginResponse
// @Router /api/v2/login [post]
func (ipg *IpgHandler) Login(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	var login vodacomgo.Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	ipg.setEnv(req)
	loginresponse, err := ipg.ipgLogin(login)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	v2response := map[string]string{}
	v2response["code"] = loginresponse.Code
	v2response["description"] = loginresponse.Description
	v2response["detail"] = loginresponse.Detail
	v2response["transactionID"] = loginresponse.TransactionID
	v2response["event_id"] = loginresponse.EventID
	v2response["sessionID"] = loginresponse.SessionID
	ipg.respondJSON(w, http.StatusCreated, v2response)

}

// C2B godoc
// @Summary Initiate Customer to Business Transaction
// @Description Initiate C2B Transaction
// @Tags c2b
// @Accept json
// @Produce json
// @Param c2b body C2B true "C2B"
// @Success 201 {object} C2BResponse
// @Router /api/v1/c2b [post]
func (ipg *IpgHandler) C2B(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	var c2b vodacomgo.C2B
	err = json.Unmarshal(body, &c2b)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	ipg.setEnv(req)
	clientcallback := c2b.CallBackDestination
	clientref := c2b.ThirdPartyReference
	c2b.CallBackChannel = "2"
	c2b.CallBackDestination = internalC2B
	ipg.DB.Set(clientref, clientcallback)
	c2bresponse, err := ipg.ipgC2B(c2b)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	ipg.respondJSON(w, http.StatusCreated, c2bresponse)

}

// B2C godoc
// @Summary Initiate Business to Customer Transaction
// @Description Initiate B2C Transaction
// @Tags b2c
// @Accept json
// @Produce json
// @Param b2c body B2C true "B2C"
// @Success 201 {object} B2CResponse
// @Router /api/v1/b2c [post]
func (ipg *IpgHandler) B2C(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	var b2c vodacomgo.B2C
	err = json.Unmarshal(body, &b2c)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadRequest, string([]byte(err.Error())))
		return
	}
	ipg.setEnv(req)
	clientcallback := b2c.CallBackDestination
	clientref := b2c.ThirdPartyReference
	b2c.CallBackChannel = "2"
	b2c.CallBackDestination = internalB2C
	ipg.DB.Set(clientref, clientcallback)
	b2cresponse, err := ipg.ipgB2C(b2c)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	ipg.respondJSON(w, http.StatusCreated, b2cresponse)

}

// C2BCallBack godoc
// @Summary Handle CallBack for a Customer to Business Transaction
// @Description Handle CallBack for a C2B Transaction and POST JSON callback to client callback url
// @Accept xml
// @Tags c2b
// @Router /api/v1/c2b_callback [post]
func (ipg *IpgHandler) C2BCallback(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		http.Error(w, "cant read body", http.StatusBadRequest)
		return
	}
	var callbackc2b vodacomgo.C2BCallbackEnvelope
	err = xml.Unmarshal(body, &callbackc2b)
	ipg.respondXML(w, http.StatusOK, []byte(vodacomgo.AckC2BT))
	cb := callbackc2b.ToResponse()
	jsonstr, err := json.Marshal(cb)
	if err != nil {
		ipg.logger.Printf("error %v\n", err)
	}
	data := new(bytes.Buffer)
	data.Write(jsonstr)
	c2bCallbackUrl = ipg.DB.Get(cb.ThirdPartyReference).(string)
	err = ipg.forwardCallback(c2bCallbackUrl, data)
	if err != nil {
		ipg.logger.Printf("error forwarding callback %v\n", err)
	}

}

// B2CCallBack godoc
// @Summary Handle CallBack for a Customer to Business Transaction
// @Description Handle CallBack for a B2C Transaction and POST JSON callback to client callback url
// @Tags b2c
// @Accept xml
// @Router /api/v1/b2c_callback [post]
func (ipg *IpgHandler) B2CCallback(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		http.Error(w, "cant read body", http.StatusBadRequest)
		return
	}
	var callbackb2c vodacomgo.B2CCallbackEnvelope
	err = xml.Unmarshal(body, &callbackb2c)
	ipg.respondXML(w, http.StatusOK, []byte(vodacomgo.AckB2CT))
	cb := callbackb2c.ToResponse()
	jsonstr, err := json.Marshal(cb)
	if err != nil {
		ipg.logger.Printf("error %v\n", err)
	}
	data := new(bytes.Buffer)
	data.Write(jsonstr)
	b2cCallbackUrl = ipg.DB.Get(cb.ThirdPartyReference).(string)
	err = ipg.forwardCallback(b2cCallbackUrl, data)
	if err != nil {
		ipg.logger.Printf("error forwarding callback %v\n", err)
	}
}

// respondJSON makes the json response with payload as json format.
func (ipg *IpgHandler) respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=utf8")
	w.WriteHeader(status)
	w.Write([]byte(response))
}

// respondError makes the error response with message as json format.
func (ipg *IpgHandler) respondError(w http.ResponseWriter, code int, message string) {
	ipg.respondJSON(w, code, map[string]string{"error": message})
}

// respondXML makes an xml response to the responsewriter using the statuscode
// and payload.
func (ipg *IpgHandler) respondXML(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	w.Write(payload)
}

// ipgLogin Does the actual login to the ipg and decodes the xml response
func (ipg *IpgHandler) ipgLogin(loginStruct vodacomgo.Login) (vodacomgo.LoginResponse, error) {
	endpoint := ":8091/insight/SOAPIn"
	addr := ipg.getIpgUrl(false) + endpoint
	xmlpayload := new(bytes.Buffer)
	if loginStruct.Username == "" || loginStruct.Password == "" {
		panic("Username and Password must be Provided.")
	}
	vodacomgo.GenLogin(xmlpayload, loginStruct)
	xmlresponsebytes, err := ipg.remotePost(addr, xmlpayload)
	if err != nil {
		ipg.logger.Fatalf("%#v\n", err)
		return vodacomgo.LoginResponse{}, err
	} else {
		loginresponse := vodacomgo.DecodeLoginResponse(xmlresponsebytes)
		parsed := loginresponse.ToResponse()
		ipg.Token = parsed.SessionID
		return parsed, nil
	}
}

// ipgC2B Does the actual C2B to the ipg and decodes the xml response
func (ipg *IpgHandler) ipgC2B(c2b vodacomgo.C2B) (vodacomgo.C2BResponse, error) {
	endpoint := ":8091/insight/SOAPIn"
	addr := ipg.getIpgUrl(false) + endpoint
	xmlpayload := new(bytes.Buffer)
	vodacomgo.GenC2B(xmlpayload, c2b)
	xmlresponsebytes, err := ipg.remotePost(addr, xmlpayload)
	if err != nil {
		ipg.logger.Fatalf("%#v\n", err)
		return vodacomgo.C2BResponse{}, err
	} else {
		c2bresponse := vodacomgo.DecodeC2BResponse(xmlresponsebytes)
		parsed := c2bresponse.ToResponse()
		return parsed, nil
	}
}

// ipgB2C Does the actual B2C to the ipg and decodes the xml response
func (ipg *IpgHandler) ipgB2C(b2c vodacomgo.B2C) (vodacomgo.B2CResponse, error) {
	endpoint := ":8094/iPG/B2C"
	addr := ipg.getIpgUrl(false) + endpoint
	xmlpayload := new(bytes.Buffer)
	vodacomgo.GenB2C(xmlpayload, b2c)
	xmlresponsebytes, err := ipg.remotePost(addr, xmlpayload)
	if err != nil {
		ipg.logger.Fatalf("%#v\n", err)
		return vodacomgo.B2CResponse{}, err
	} else {
		b2cresponse := vodacomgo.DecodeB2CResponse(xmlresponsebytes)
		parsed := b2cresponse.ToResponse()
		return parsed, nil
	}
}

// remotePost is a helper function that does a post request with the data as
// body to the specified address.
func (ipg *IpgHandler) remotePost(addr string, data io.Reader) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, addr, data)
	if err != nil {
		ipg.logger.Fatalf("Error creating request: %#v\n", err)
		return nil, err
	}
	resp, err := ipg.client.Do(request)
	if err != nil {
		ipg.logger.Fatalf("Error sending request: %#v\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	ipg.logger.Printf("POST: %v  => %v\n", addr, resp.Status)
	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ipg.logger.Fatalf("Error reading HTTP response: %#v\n", err)
		return nil, err
	}
	return responseBytes, err

}

// forwardCallback post some parsed callback to the client's specified url.
func (ipg *IpgHandler) forwardCallback(addr string, data io.Reader) error {
	request, err := http.NewRequest(http.MethodPost, addr, data)
	if err != nil {
		ipg.logger.Fatalf("Error creating request: %#v\n", err)
		return err
	}
	client := Decorate(http.DefaultClient, Header("Content-Type", "application/json"))
	resp, err := client.Do(request)
	if err != nil {
		ipg.logger.Fatalf("Error sending request: %#v\n", err)
		return err
	}
	defer resp.Body.Close()
	ipg.logger.Printf("POST: %v  => %v\n", addr, resp.Status)
	if resp.StatusCode == 500 {
		body, err := ioutil.ReadAll(resp.Body)
		ipg.logger.Printf("Traceback:\n %v\n%v\n", string(body), err)
	}
	return nil
}

type Login struct {
	Username string
	Password string
} //@name Login

type Status struct {
	Status string `json:"status"`
} //@name Status

type LoginResponse struct {
	Code          string `json:"code"`
	Description   string `json:"description"`
	Detail        string `json:"detail"`
	TransactionID string `json:"transactionID"`
	EventID       string `json:"event_id"`
	SessionID     string `json:"SessionID"`
} //@name LoginResponse

type LoginResponse2 struct {
	Code          string `json:"code"`
	Description   string `json:"description"`
	Detail        string `json:"detail"`
	TransactionID string `json:"transactionID"`
	EventID       string `json:"event_id"`
	Token         string `json:"token"`
} //@name LoginResponseV1

type C2B struct {
	Token               string
	CustomerMSISDN      string
	ServiceProviderCode string
	Currency            string
	Amount              string
	Date                string
	ThirdPartyReference string
	CommandID           string
	Language            string
	CallBackChannel     string
	CallBackDestination string
	Surname             string
	Initials            string
} //@name C2B

type C2BResponse struct {
	Amount              string `json:"Amount"`
	CallBackChannel     string `json:"CallBackChannel"`
	CallBackDestination string `json:"CallBackDestination"`
	Code                string `json:"code"`
	CommandId           string `json:"CommandID"`
	Currency            string `json:"Currency"`
	CustomerMSISDN      string `json:"CustomerMSISDN"`
	Date                string `json:"Date"`
	Description         string `json:"description"`
	Detail              string `json:"detail"`
	EventID             string `json:"event_id"`
	Initials            string `json:"Initials"`
	InsightReference    string `json:"InsightReference"`
	Language            string `json:"Language"`
	ResponseCode        string `json:"ResponseCode"`
	ServiceProviderCode string `json:"ServiceProviderCode"`
	Surname             string `json:"Surname"`
	ThirdPartyReference string `json:"ThirdPartyReference"`
	TransactionID       string `json:"transactionID"`
} //@name C2BResponse

type B2C struct {
	Token               string
	ServiceProviderName string
	CustomerMSISDN      string
	Currency            string
	Amount              string
	TransactionDateTime string
	Shortcode           string
	Language            string
	ThirdPartyReference string
	CallBackChannel     string
	CallBackDestination string
	CommandID           string
} //@name B2C

type B2CResponse struct {
	Amount              string `json:"Amount"`
	CallBackChannel     string `json:"CallBackChannel"`
	CallBackDestination string `json:"CallBackDestination"`
	Code                string `json:"code"`
	CommandID           string `json:"CommandID"`
	Currency            string `json:"Currency"`
	CustomerMSISDN      string `json:"CustomerMSISDN"`
	Description         string `json:"description"`
	Detail              string `json:"detail"`
	EventID             string `json:"event_id"`
	InsightReference    string `json:"InsightReference"`
	Language            string `json:"Language"`
	ResponseCode        string `json:"ResponseCode"`
	ServiceProviderName string `json:"ServiceProviderName"`
	Shortcode           string `json:"Shortcode"`
	ThirdPartyReference string `json:"ThirdPartyReference"`
	TransactionDateTime string `json:"TransactionDateTime"`
	TransactionID       string `json:"transactionID"`
} //@name B2CResponse
