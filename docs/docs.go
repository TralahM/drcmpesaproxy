// GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag

package docs

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/alecthomas/template"
	"github.com/swaggo/swag"
)

var doc = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{.Description}}",
        "title": "{{.Title}}",
        "termsOfService": "https://blog.tralahm.com",
        "contact": {
            "name": "API Support",
            "email": "briantralah@gmail.com"
        },
        "license": {
            "name": "GNU GENERAL PUBLIC LICENSE",
            "url": "http://www.gnu.org/licenses/"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/v1/b2c": {
            "post": {
                "description": "Initiate B2C Transaction",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "b2c"
                ],
                "summary": "Initiate Business to Customer Transaction",
                "parameters": [
                    {
                        "description": "B2C",
                        "name": "b2c",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.B2C"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/main.B2CResponse"
                        }
                    }
                }
            }
        },
        "/api/v1/b2c_callback": {
            "post": {
                "description": "Handle CallBack for a B2C Transaction and POST JSON callback to client callback url",
                "consumes": [
                    "text/xml"
                ],
                "tags": [
                    "b2c"
                ],
                "summary": "Handle CallBack for a Customer to Business Transaction"
            }
        },
        "/api/v1/c2b": {
            "post": {
                "description": "Initiate C2B Transaction",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "c2b"
                ],
                "summary": "Initiate Customer to Business Transaction",
                "parameters": [
                    {
                        "description": "C2B",
                        "name": "c2b",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.C2B"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/main.C2BResponse"
                        }
                    }
                }
            }
        },
        "/api/v1/c2b_callback": {
            "post": {
                "description": "Handle CallBack for a C2B Transaction and POST JSON callback to client callback url",
                "consumes": [
                    "text/xml"
                ],
                "tags": [
                    "c2b"
                ],
                "summary": "Handle CallBack for a Customer to Business Transaction"
            }
        },
        "/api/v1/health": {
            "get": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "health"
                ],
                "summary": "Check Health Status",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Status"
                        }
                    }
                }
            }
        },
        "/api/v1/login": {
            "post": {
                "description": "Login to the MPESA Ipg with the credentials and return JSON response.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "login"
                ],
                "summary": "Authenticate against the Remote IPG",
                "parameters": [
                    {
                        "description": "Login",
                        "name": "credentials",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/main.Login"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/main.LoginResponse"
                        }
                    }
                }
            }
        },
        "/api/v1/ready": {
            "get": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "ready"
                ],
                "summary": "Check Readiness Status",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/main.Status"
                        }
                    }
                }
            }
        },
        "/swagger.json": {
            "get": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "swagger"
                ],
                "summary": "Get API Swagger Definition",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "main.B2C": {
            "type": "object",
            "properties": {
                "amount": {
                    "type": "string"
                },
                "callBackChannel": {
                    "type": "string"
                },
                "callBackDestination": {
                    "type": "string"
                },
                "commandID": {
                    "type": "string"
                },
                "currency": {
                    "type": "string"
                },
                "customerMSISDN": {
                    "type": "string"
                },
                "language": {
                    "type": "string"
                },
                "serviceProviderName": {
                    "type": "string"
                },
                "shortcode": {
                    "type": "string"
                },
                "thirdPartyReference": {
                    "type": "string"
                },
                "token": {
                    "type": "string"
                },
                "transactionDateTime": {
                    "type": "string"
                }
            }
        },
        "main.B2CResponse": {
            "type": "object",
            "properties": {
                "Amount": {
                    "type": "string"
                },
                "CallBackChannel": {
                    "type": "string"
                },
                "CallBackDestination": {
                    "type": "string"
                },
                "CommandID": {
                    "type": "string"
                },
                "Currency": {
                    "type": "string"
                },
                "CustomerMSISDN": {
                    "type": "string"
                },
                "InsightReference": {
                    "type": "string"
                },
                "Language": {
                    "type": "string"
                },
                "ResponseCode": {
                    "type": "string"
                },
                "ServiceProviderName": {
                    "type": "string"
                },
                "Shortcode": {
                    "type": "string"
                },
                "ThirdPartyReference": {
                    "type": "string"
                },
                "TransactionDateTime": {
                    "type": "string"
                },
                "code": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "detail": {
                    "type": "string"
                },
                "event_id": {
                    "type": "string"
                },
                "transactionID": {
                    "type": "string"
                }
            }
        },
        "main.C2B": {
            "type": "object",
            "properties": {
                "amount": {
                    "type": "string"
                },
                "callBackChannel": {
                    "type": "string"
                },
                "callBackDestination": {
                    "type": "string"
                },
                "commandID": {
                    "type": "string"
                },
                "currency": {
                    "type": "string"
                },
                "customerMSISDN": {
                    "type": "string"
                },
                "date": {
                    "type": "string"
                },
                "initials": {
                    "type": "string"
                },
                "language": {
                    "type": "string"
                },
                "serviceProviderCode": {
                    "type": "string"
                },
                "surname": {
                    "type": "string"
                },
                "thirdPartyReference": {
                    "type": "string"
                },
                "token": {
                    "type": "string"
                }
            }
        },
        "main.C2BResponse": {
            "type": "object",
            "properties": {
                "Amount": {
                    "type": "string"
                },
                "CallBackChannel": {
                    "type": "string"
                },
                "CallBackDestination": {
                    "type": "string"
                },
                "CommandID": {
                    "type": "string"
                },
                "Currency": {
                    "type": "string"
                },
                "CustomerMSISDN": {
                    "type": "string"
                },
                "Date": {
                    "type": "string"
                },
                "Initials": {
                    "type": "string"
                },
                "InsightReference": {
                    "type": "string"
                },
                "Language": {
                    "type": "string"
                },
                "ResponseCode": {
                    "type": "string"
                },
                "ServiceProviderCode": {
                    "type": "string"
                },
                "Surname": {
                    "type": "string"
                },
                "ThirdPartyReference": {
                    "type": "string"
                },
                "code": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "detail": {
                    "type": "string"
                },
                "event_id": {
                    "type": "string"
                },
                "transactionID": {
                    "type": "string"
                }
            }
        },
        "main.Login": {
            "type": "object",
            "properties": {
                "password": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "main.LoginResponse": {
            "type": "object",
            "properties": {
                "Password": {
                    "type": "string"
                },
                "SessionID": {
                    "type": "string"
                },
                "Username": {
                    "type": "string"
                },
                "code": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "detail": {
                    "type": "string"
                },
                "event_id": {
                    "type": "string"
                },
                "transactionID": {
                    "type": "string"
                }
            }
        },
        "main.Status": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string"
                }
            }
        }
    }
}`

type swaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = swaggerInfo{
	Version:     "1.0",
	Host:        "ipg.betmondenge.com",
	BasePath:    "/",
	Schemes:     []string{},
	Title:       "DRC MPESA Proxy REST API",
	Description: "This is a service for interacting with Vodacom's DRC MPESA SOAP Integrated Payment Gateway.",
}

type s struct{}

func (s *s) ReadDoc() string {
	sInfo := SwaggerInfo
	sInfo.Description = strings.Replace(sInfo.Description, "\n", "\\n", -1)

	t, err := template.New("swagger_info").Funcs(template.FuncMap{
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
	}).Parse(doc)
	if err != nil {
		return doc
	}

	var tpl bytes.Buffer
	if err := t.Execute(&tpl, sInfo); err != nil {
		return doc
	}

	return tpl.String()
}

func init() {
	swag.Register(swag.Name, &s{})
}
