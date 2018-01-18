package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/pjebs/restgate"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

var apiSecret string

func main() {

	// Secret to sign JWT with
	apiSecret = "ultrasecret"

	app := negroni.New()

	//These middleware is common to all routes
	app.Use(negroni.NewRecovery())
	app.Use(negroni.NewLogger())
	app.UseHandler(NewRoute())
	http.Handle("/", context.ClearHandler(app))
	app.Run(":8080")
}

func NewRoute() *mux.Router {

	//Create subrouters
	//Rest API protected via static method after calling /api/login
	//this will return a valid HMAC signed token to be used on subsequent calls
	//to the rest of the APIs
	loginRouter := mux.NewRouter()
	loginRouter.HandleFunc("/api/login", LoginHandler())

	//A second Rest API Endpoint handler that uses the JWT method
	jwtRouter := mux.NewRouter()
	jwtRouter.HandleFunc("/api/get", ApiGetHandler())

	//Create negroni instance to handle different middlewares for different api routes
	loginRest := negroni.New()
	loginRest.Use(restgate.New("X-Auth-Key", "X-Auth-Secret", restgate.Static, restgate.Config{Context: C, Key: []string{"user1"},
		Secret: []string{"password1"}, HTTPSProtectionOff: true}))
	loginRest.UseHandler(loginRouter)

	jwtRest := negroni.New()
	jwtRest.Use(restgate.New("Authorization", "", restgate.JWT, restgate.Config{JWT: restgate.JWTConfig{Claims: J, Algorithm: restgate.HMAC,
		SigningMethod: jwt.SigningMethodHS256, HMACSecret: apiSecret}, HTTPSProtectionOff: true}))
	jwtRest.UseHandler(jwtRouter)

	//Create main router
	mainRouter := mux.NewRouter().StrictSlash(true)
	mainRouter.HandleFunc("/", MainHandler())  //Main Handler -> Use your own
	mainRouter.Handle("/api/login", loginRest) //This endpoint is protected by RestGate via hardcoded KEYs
	mainRouter.Handle("/api/get", jwtRest)     //This endpoint is protected by RestGate via JWT token
	return mainRouter

}

//Optional Context - If not required, remove 'Context: C' or alternatively pass nil (see above)
//NB: Endpoint handler can determine the key used to authenticate via: context.Get(r, 0).(string)
func C(r *http.Request, authenticatedKey string) {
	context.Set(r, 0, authenticatedKey) // Read http://www.gorillatoolkit.org/pkg/context about setting arbitary context key
}

//Optional function to add JWT claims via name/value - If the claims on the token are not required, remove 'Context: J' or alternatively pass nil
//NB: Endpoint handler can get all JWT claims
func J(r *http.Request, name string, value interface{}) {
	context.Set(r, name, value)
}

//Endpoint Handlers
func LoginHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		//Get the value of X-Auth-Key from the context
		key := context.Get(r, 0)

		//Create the claims
		claims :=
			jwt.StandardClaims{
				Subject:   key.(string), // This token belong to this user
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), // Expire after just 5 minutes
				Issuer:    "restgate-jwt-example",
			}

		// Create the token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(apiSecret))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Authentication", fmt.Sprintf("Bearer %s", tokenString))
		fmt.Fprint(w, "/api/login -> loginHandler - protected by RestGate (Static Mode)\n")
	}
}

func ApiGetHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// If there is no context then don'tr try to get the claims
		if r.Context() == nil {
			fmt.Fprint(w, "/api/get -> apiGetHandler - protected by RestGate (JWT mode)\n")
			return
		}

		//Get information from the token's claims via context
		user, _ := context.Get(r, "sub").(string)
		issued, _ := context.Get(r, "iat").(float64)
		expires, _ := context.Get(r, "exp").(float64)
		issuer, _ := context.Get(r, "iss").(string)

		//Convert the issued and expires values to int64 and parse them as text strings
		issuedDate := time.Unix(int64(issued), 0)
		expiresDate := time.Unix(int64(expires), 0)

		fmt.Fprintf(w, "/api/get -> apiGetHandler - protected by RestGate (JWT mode)\nWelcome back %s!\n\nToken Information:\nIssued By: %s\nOn: %s\nExpires: %s\n",
			user, issuer, issuedDate.UTC().String(), expiresDate.UTC().String())

	}
}

func MainHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/ -> MainHandler - not protected by RestGate\n")
	}
}
