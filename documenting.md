### Generate Swagger documentation
Let us divide this whole process of API documentation into 3 steps:

1. Adding annotations in code
2. Generating Swagger specs (swagger.json and swagger.yaml)
3. Serving the Swagger UI using the specs generated in the previous step

#### General API Info

// @title DRC Mpesa Proxy (JSON-SOAP-JSON) API
// @version 1.0
// @description This is a service for interacting with Vodacom's DRC MPESA SOAP Integrated Payment Gateway.
// @termsOfService https://blog.tralahm.com
// @contact.name API Support
// @contact.email briantralah@gmail.com
// @license.name GNU GENERAL PUBLIC LICENSE
// @license.url http://www.gnu.org/licenses/
// @host ipg.betmondenge.com
// @BasePath /

#### API Operations Annotations

// GetHealth godoc
// @Summary Check Health Status
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {}
// @Router /api/v1/health [get]

type Login struct{
    vodacomgo.Login
}
type LoginResponse struct{
    vodacomgo.LoginResponse
}

// C2B godoc
// @Summary Initiate Customer to Business Transaction
// @Description Initiate C2B Transaction
// @Tags c2b
// @Accept json
// @Produce json
// @Param credentials body C2B true "C2B"
// @Success 201 {object} C2BResponse
// @Router /api/v1/c2b [post]


// B2C godoc
// @Summary Initiate Business to Customer Transaction
// @Description Initiate B2C Transaction
// @Tags b2c
// @Accept json
// @Produce json
// @Param credentials body B2C true "B2C"
// @Success 201 {object} B2CResponse
// @Router /api/v1/b2c [post]

// C2BCallBack godoc
// @Summary Handle CallBack for a Customer to Business Transaction
// @Description Handle CallBack for a C2B Transaction
// @Tags c2b
// @Accept xml
// @Produce xml
// @Param credentials body C2BCallbackEnvelope true "C2B"
// @Success 200 {object} C2BResponse
// @Router /api/v1/c2b_callback [post]


// B2CCallBack godoc
// @Summary Handle CallBack for a Customer to Business Transaction
// @Description Handle CallBack for a B2C Transaction
// @Tags b2c
// @Accept xml
// @Produce xml
// @Param credentials body B2CCallbackEnvelope true "B2C"
// @Success 200 {object} B2CResponse
// @Router /api/v1/b2c_callback [post]


