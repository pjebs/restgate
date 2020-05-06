RestGate for Go [![GoDoc](http://godoc.org/github.com/pjebs/restgate?status.svg)](http://godoc.org/github.com/pjebs/restgate)
===============


RestGate middleware provides secure authentication for your REST API endpoints.
It is super easy to use and elegantly designed. It will save you time.

It can be used with almost all frameworks including [Negroni](https://github.com/codegangsta/negroni), [Martini](http://martini.codegangsta.io/), [Gocraft/Web](https://github.com/gocraft/web), [Gin](https://gin-gonic.github.io/gin/) and [Goji](https://goji.io/).

RestGate does only these things:

* Protects Endpoints by requiring authentication *via* the HTTP Request Header
* Multiple Keys and optional corresponding Secrets
* Supports JSON Web Tokens [JWT](https://jwt.io/introduction/)
* Supports both RSA and HMAC signed tokens
* Keys (and corresponding Secrets) can be configured in code [Static mode]
* Keys (and corresponding Secrets) can be stored in any SQL database [Database mode]
* Keys (and corresponding Secrets) are not needed in [JWT mode]
* JSON Error Responses are fully customizable
* Utilize a Context (i.e. Gorilla Context) to pass authenticated KEY to later middleware and endpoint handlers and optionally JWT claims
* Protection from timing-attacks (Authentication Verification)
* HTTPS Protection


Since Go is a new programming language, I have made the documentation and code as easy to understand as possible. Studying the code can be a great learning experience.

To use with the popular [Gin](https://gin-gonic.github.io/gin/) framework, refer to here: https://github.com/pjebs/restgate/issues/4

Installation
-------------

```shell
go get -u github.com/pjebs/restgate
```

Optional - if you want to [utilize a Context](http://elithrar.github.io/article/map-string-interface/):

```shell
go get -u github.com/gorilla/context
```

Usage
------

```go
package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pjebs/restgate"
	"github.com/codegangsta/negroni"
	_ "github.com/go-sql-driver/mysql" //_ "github.com/lib/pq" (For PostgreSQL)
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

func init() { //On Google App Engine you don't use main()

	app := negroni.New()

	//These middleware is common to all routes
	app.Use(negroni.NewRecovery())
	app.Use(negroni.NewLogger())
	app.UseHandler(NewRoute())
	http.Handle("/", context.ClearHandler(app))
	//app.Run(":8080") //On Google App Engine, you don't use this
}

func NewRoute() *mux.Router {

	//Create subrouters
	restRouter := mux.NewRouter()
	restRouter.HandleFunc("/api", Handler1()) //Rest API Endpoint handler -> Use your own

	rest2Router := mux.NewRouter()
	rest2Router.HandleFunc("/api2", Handler2()) //A second Rest API Endpoint handler -> Use your own

	rest3Router := mux.NewRouter()
	rest3Router.HandleFunc("/api3", Handler3()) //A third Rest API Endpoint handler -> Use your own

	rest4Router := mux.NewRouter()
	rest4Router.HandleFunc("/api4", Handler4()) //A fourth Rest API Endpoint handler -> Use your own

	//Create negroni instance to handle different middlewares for different api routes
	negRest := negroni.New()
	negRest.Use(restgate.New("X-Auth-Key", "X-Auth-Secret", restgate.Static, restgate.Config{Context: C, Key: []string{"12345"}, Secret: []string{"secret"}}))
	negRest.UseHandler(restRouter)

	negRest2 := negroni.New()
	negRest2.Use(restgate.New("X-Auth-Key", "X-Auth-Secret", restgate.Database, restgate.Config{DB: SqlDB(), TableName: "users", Key: []string{"keys"}, Secret: []string{"secrets"}}))
	negRest2.UseHandler(rest2Router)

	negRest3 := negroni.New()
	negRest3.Use(restgate.New("Authorization", "", restgate.JWT, restgate.Config{Context: C, JWT: restgate.JWTConfig{Algorithm: restgate.RSA,
		Claims: J, SigningMethod: jwt.SigningMethodRS256, RSAPublicKeyData: RSAKeyData()},}))
	negRest3.UseHandler(rest3Router)

	negRest4 := negroni.New()
	negRest4.Use(restgate.New("Authorization", "", restgate.JWT, restgate.Config{JWT: restgate.JWTConfig{Algorithm: restgate.HMAC,
		SigningMethod: jwt.SigningMethodHS256, HMACSecret: "secret"},}))
	negRest4.UseHandler(rest4Router)

	//Create main router
	mainRouter := mux.NewRouter().StrictSlash(true)
	mainRouter.HandleFunc("/", MainHandler()) //Main Handler -> Use your own
	mainRouter.Handle("/api", negRest)        //This endpoint is protected by RestGate via hardcoded KEYs
	mainRouter.Handle("/api2", negRest2)      //This endpoint is protected by RestGate via KEYs stored in a database
	mainRouter.Handle("/api3", negRest3)      //This endpoint is protected by RestGate via a RSA signed JWT
	mainRouter.Handle("/api4", negRest4)      //This endpoint is protected by RestGate via a HMAC signed JWT

	return mainRouter

}

//Optional Context - If not required, remove 'Context: C' or alternatively pass nil (see above)
//NB: Endpoint handler can determine the key used to authenticate via: context.Get(r, 0).(string)
func C(r *http.Request, authenticatedKey string) {
	context.Set(r, 0, authenticatedKey) // Read http://www.gorillatoolkit.org/pkg/context about setting arbitary context key
}

//Optional function to add JWT claims via name/value - If the claims on the token are not required, remove 'Context: J' or alternatively pass nil
//NB: Endpoint handler can get all JWT claims (name and value)
func J(r *http.Request, name string, value interface{}) {
	context.Set(r, name, value)
}

//Optional Database
func SqlDB() *sql.DB {

	DB_TYPE := "mysql"
	DB_HOST := "localhost"
	DB_PORT := "3306"
	DB_USER := "root"
	DB_NAME := "mydatabase"
	DB_PASSWORD := ""

	openString := DB_USER + ":" + DB_PASSWORD + "@tcp(" + DB_HOST + ":" + DB_PORT + ")/" + DB_NAME

	db, err := sql.Open(DB_TYPE, openString)
	if err != nil {
		return nil
	}

	return db
	// defer db.Close()

}

//for RSA signed tokens we need to get the RSA public key contents
func RSAKeyData() []byte {
	keydata, err := ioutil.ReadFile("public-key.pem")
	if err != nil {
		return nil
	}
	return keydata
}

//Endpoint Handlers
func Handler1() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/api -> Handler1 - protected by RestGate (Static Mode)\n")
	}
}

func Handler2() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/api2 -> Handler2 - protected by RestGate (database mode)\n")
	}
}

func Handler3() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/api3 -> Handler3 - protected by RestGate (JWT mode with RSA signature)\n")
	}
}

func Handler4() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/api4 -> Handler4 - protected by RestGate (JWT mode with HMAC signature)\n")
	}
}

func MainHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "/ -> MainHandler - not protected by RestGate\n")
	}
}


```

Methods
--------

```go
func New(headerKeyLabel string, headerSecretLabel string, as AuthenticationSource, config Config) *RESTGate
```

`headerKeyLabel string` - What the header field name should be for required **KEY**.

`headerSecretLabel string` - *Optional* What the header header field name should be for required **SECRET**. This can be `""` if you don't intend to configure a **SECRET** or if you're using `restgate.JWT`.

`as AuthenticationSource` - Can be `restgate.Static`, `restgate.Database.` or `restgate.JWT`. If Static is chosen, then KEY(s) and SECRET(s) must be hardcoded.

`config Config` - A struct used to configure extra settings such as hardcoded **KEYS** and **SECRETS**, custom JSON error messages, Database settings (for `restgate.Database` mode), JWT settings (for `restgate.JWT` mode, using the `restgate.JWTConfig` struct with it's own context function) and context function. **PostgreSQL** users must set `Postgres` to true.

Settings
---------

If `AuthenticationSource==restgate.Database,` then **KEY** and **SECRET** fields in the `Config` struct represent the field names in the database table.

If `AuthenticationSource==restgate.JWT,` then **KEY** and **SECRET** fields in the `Config` struct are not needed, but extra configuration parameters using `restgate.JWTConfig` are needed

If you want to provide custom JSON error messages, you can pass something like this into the `Config` Struct:


```go
ErrorMessages: map[int]map[string]string{
			1:  map[string]string{"code": "1", "error": "No Key Or Secret"},
			2:  map[string]string{"code": "2", "error": "Unauthorized Access"},
			3:  map[string]string{"code": "3", "error": "Please use HTTPS connection"},
			99: map[string]string{"code": "99", "error": "Software Developers have not setup authentication correctly"},
		}
```

Remember, if you want to modify the default error codes and messages, you should provide error messages for all 4. Don't change the number 1,2,3 and 99 on the far left hand side. They are for internal use.

It may be more useful to use the [`"github.com/pjebs/jsonerror"`](https://github.com/pjebs/jsonerror) package for setting custom error messages. See [`restgate.go@L90`](https://github.com/pjebs/restgate/blob/master/restgate.go#L90) for an example.


Debugging
---------

Set the `Debug` field to `true` in the `Config` struct. This will give extra details on why RestGate may not be set up correctly. Turn off `Debug` mode when your website is live.


FAQ
----

**How do I actually authenticate?**

When the user wants to use your API (i.e. send requests to your RestGate protected endpoints), they must modify the header of their request. They can't just use ordinary POST requests. For curl, the command is `-H.` [See this article](http://stackoverflow.com/questions/356705/how-to-send-a-header-using-a-http-request-through-a-curl-call).

For the code sample above, the HTTP Request Header will need to contain `X-Auth-Key: ***A valid Key goes here***` and `X-Auth-Secret: ***A valid Secret goes here***.`

If the Key/Secret is invalid, the user **will not** be able to access your endpoint. Instead they will be returned a JSON response: `Unauthorized Access` (provided you didn't customize the default error messages).

**How do I actually authenticate with JWT?**

An example API server is available in the [examples](https://github.com/pjebs/restgate/examples/jwt) directory

**Where should I put RestGate in my middleware stack?**

You should put it directly after Recovery, Logging and HTTPS Security middleware.

**How do I make this package even more secure?**

You MUST use middleware such as [Secure](https://github.com/unrolled/secure) to ensure all requests are via a HTTPS connection. Of course, the connection must also use a HTTPS connection, so purchase a [SSL certificate](http://www.rapidssl.com/).

By default, basic HTTPS Protection is offered. This should be kept enabled for Production. For Local Development, you can set `HTTPSProtectionOff=true` in the `Config` struct to **allow** HTTP connections.

If you are using Google App Engine - **Flexible** Environment, then set `GAE_FlexibleEnvironment: true`. Keep this set to false (default) under all other circumstances including Google App Engine - **Standard** Environment!

**How do I set up the database?**

Make sure that the field you use to store the Keys are set to **UNIQUE** and **NOT NULL** (or **PRIMARY KEY**). That ensures that identical keys are prohibited. It also speeds up the query search. Also ensure that you set the Database name when you create the `sql.DB` struct.

**I'm using hardcoded Key values. How do I set up the corresponding Secrets?**

See the example code above. The number of Secrets configured must be equal to or less than the number of Keys configured. The index of the Key slice corresponds to the same index in the Secret slice. If you want to disable the Secret for a particular Key, set it to `"".` If the number of Keys outnumber the number of Secrets, then the outnumbering Keys will be not have a corresponding Secret (equivalent to the Secret being disabled for that particular Key).

**What's the difference between a Key and Secret?**

There is no hard and fast rule and you can use it however you want.

Common usage:

If you want to use a **Key** and **Secret**, then the **Key** is equivalent to a *username* and the **Secret** is equivalent to a *password*. The **Secret** should be kept *secret*. The **Key** can be used to *identify* the user of the REST API services.

If you are only using a **KEY**, then usually it is used to *identify* the user of the REST API service. It also operates as the *password* so keep it private.

**PANIC: runtime error: invalid memory address or nil pointer dereference**

This usually occurs at this point: `<negroni.New()>.Use(restgate.New(...))`.

`restgate.New(...)` returns a nil pointer if there is a configuration error. A nil pointer will cause Negroni to panic. This is beneficial because you will notice it instantly and fix up the configuration.

**How can I generate a valid JWT token**
JSON Web tokens can be created on [jwt.io](http://jwt.io).

Other Useful Packages
------------

Check out [`"github.com/pjebs/jsonerror"`](https://github.com/pjebs/jsonerror) package. It will make error-handling, debugging and diagnosis much simpler and more elegant for all your Go projects.


Check out [`"github.com/pjebs/optimus-go"`](https://github.com/pjebs/optimus-go) package. Internal ID hashing and Obfuscation using Knuth's Algorithm. (For databases etc)

Final Notes
------------

If you found this package useful, please **Star** it on github. Feel free to fork or provide pull requests. Any bug reports will be warmly received.


[PJ Engineering and Business Solutions Pty. Ltd.](http://www.pjebs.com.au)
