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

// Login godoc
// @Summary Authenticate against the Remote IPG
// @Description Login to the MPESA Ipg with the credentials and return JSON response.
// @Tags login
// @Accept json
// @Produce json
// @Param credentials body vodacomgo.Login true "Login"
// @Success 201 {object} vodacomgo.LoginResponse
// @Router /api/v1/login [post]

