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
	"github.com/tralahm/vodacomgo"
)

var (
	ServPort       = getEnv("PORT", "8000")
	c2bCallbackUrl = getEnv("CLIENT_C2B_CALLBACK_URL", "https://api.betmondenge.com/en/api/c2b_vodacash/")
	b2cCallbackUrl = getEnv("CLIENT_B2C_CALLBACK_URL", "https://api.betmondenge.com/en/api/b2c_vodacash/")
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Logger)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Recoverer)

	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"https://*", "http://*"},
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
		ExposedHeaders:   []string{"Link", "RequestID"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	handler := NewIpgHandler()
	r.Get("/api/v1/health", handler.Health)
	r.Get("/api/v1/ready", handler.Ready)
	r.Post("/api/v1/login", handler.Login)
	r.Post("/api/v1/c2b", handler.C2B)
	r.Post("/api/v1/b2c", handler.B2C)
	r.Post("/api/v1/vodacash_c2b_callback", handler.C2BCallback)
	r.Post("/api/v1/vodacash_b2c_callback", handler.B2CCallback)
	r.Post("/api/v1/c2b_callback", handler.C2BCallback)
	r.Post("/api/v1/b2c_callback", handler.B2CCallback)

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
}

func NewIpgHandler() *IpgHandler {
	logger := log.New(os.Stdout, "drcmpesaproxy: ", log.Ldate|log.Ltime|log.Lshortfile)
	hs := &IpgHandler{
		client:  Decorate(http.DefaultClient, Header("Accept", "application/xml,text/xml")),
		logger:  logger,
		sandbox: false,
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

func (ipg *IpgHandler) Health(w http.ResponseWriter, req *http.Request) {
	ipg.respondJSON(w, 200, map[string]string{"status": "healthy"})
}

func (ipg *IpgHandler) Ready(w http.ResponseWriter, req *http.Request) {
	ipg.respondJSON(w, 200, map[string]string{"status": "ready"})
}

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
	ipg.respondJSON(w, http.StatusCreated, loginresponse)

}

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
	c2bresponse, err := ipg.ipgC2B(c2b)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	ipg.respondJSON(w, http.StatusCreated, c2bresponse)

}

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
	b2cresponse, err := ipg.ipgB2C(b2c)
	if err != nil {
		ipg.logger.Printf("Error reading body: %v\n", err)
		ipg.respondError(w, http.StatusBadGateway, string([]byte(err.Error())))
		return
	}
	ipg.respondJSON(w, http.StatusCreated, b2cresponse)

}

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
	err = ipg.forwardCallback(c2bCallbackUrl, data)
	if err != nil {
		ipg.logger.Printf("error forwarding callback %v\n", err)
	}

}

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

func (ipg *IpgHandler) respondXML(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	w.Write(payload)
}

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
