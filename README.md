RestGate for Go [![GoDoc](http://godoc.org/github.com/pjebs/restgate?status.svg)](http://godoc.org/github.com/pjebs/restgate)
===============


RestGate middleware provides secure authentication for your REST API endpoints.
It is super easy to use and elegantly designed. It will save you time.

It can be used with almost all frameworks including [Negroni](https://github.com/codegangsta/negroni), [Martini](http://martini.codegangsta.io/), [Gocraft/Web](https://github.com/gocraft/web), [Gin](https://gin-gonic.github.io/gin/) and [Goji](https://goji.io/).

RestGate does only these things:

* Protects Endpoints by requiring authentication *via* the HTTP Request Header
* Multiple Keys and optional corresponding Secrets
* Keys (and corresponding Secrets) can be configured in code [Static mode]
* Keys (and corresponding Secrets) can be stored in any SQL database [Database mode]
* JSON Error Responses are fully customizable
* Utilize a Context (i.e. Gorilla Context) to pass authenticated KEY to later middleware and endpoint handlers
* Protection from timing-attacks (Authentication Verification)



Since Go is a new programming language, I have made the documentation and code as easy to understand as possible. Studying the code can be a great learning experience.


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
	"github.com/codegangsta/negroni"
	_ "github.com/go-sql-driver/mysql" //_ "github.com/lib/pq" (For PostgreSQL)
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/pjebs/restgate"
	"net/http"
)

func init() { //On Google App Engine you don't use main()

	app := negroni.New()

	//These middleware is common to all routes
	app.Use(negroni.NewRecovery())
	app.Use(negroni.NewLogger())
	app.UseHandler(NewRoute())
	http.Handle("/", context.ClearHandler(app))
	// app.Run(":8080") //On Google App Engine, you don't use this
}


func NewRoute() *mux.Router {

	//Create subrouters
	restRouter := mux.NewRouter()
	restRouter.HandleFunc("/api", Handler1()) //Rest API Endpoint handler -> Use your own

	rest2Router := mux.NewRouter()
	rest2Router.HandleFunc("/api2", Handler2()) //A second Rest API Endpoint handler -> Use your own

	//Create negroni instance to handle different middlewares for different api routes
	negRest := negroni.New()
	negRest.Use(restgate.New("X-Auth-Key", "X-Auth-Secret", restgate.Static, restgate.Config{Context: C, Key: []string{"12345"}, Secret: []string{"secret"}}))
	negRest.UseHandler(restRouter)

	negRest2 := negroni.New()
	negRest2.Use(restgate.New("X-Auth-Key", "X-Auth-Secret", restgate.Database, restgate.Config{DB: SqlDB(), TableName: "users", Key: []string{"keys"}, Secret: []string{"secrets"}}))
	negRest2.UseHandler(rest2Router)

	//Create main router
	mainRouter := mux.NewRouter().StrictSlash(true)
	mainRouter.HandleFunc("/", MainHandler()) //Main Handler -> Use your own
	mainRouter.Handle("/api", negRest) //This endpoint is protected by RestGate via hardcoded KEYs
	mainRouter.Handle("/api2", negRest2) //This endpoint is protected by RestGate via KEYs stored in a database

	return mainRouter

}

//Optional Context - If not required, remove 'Context: C' or alternatively pass nil (see above)
//NB: Endpoint handler can determine the key used to authenticate via: context.Get(r, 0).(string)
func C(r *http.Request, authenticatedKey string) {
	context.Set(r, 0, authenticatedKey) // Read http://www.gorillatoolkit.org/pkg/context about setting arbitary context key
}

//Optional Database
func SqlDB() *sql.DB {
	
	DB_TYPE     := "mysql"
	DB_HOST     := "localhost"
	DB_PORT     := "3306"
	DB_USER     := "root"
	DB_NAME     := "mydatabase"
	DB_PASSWORD := ""

	openString := DB_USER + ":" + DB_PASSWORD + "@tcp(" + DB_HOST + ":" + DB_PORT + ")/" + DB_NAME

	db, err := sql.Open(DB_TYPE, openString)
	if err != nil {
		return nil
	}

	return db
	// defer db.Close()

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

`headerSecretLabel string` - *Optional* What the header header field name should be for required **SECRET**. This can be `""` if you don't intend to configure a **SECRET**.

`as AuthenticationSource` - Can be `restgate.Static` or `restgate.Database.` If Static is chosen, then KEY(s) and SECRET(s) must be hardcoded.

`config Config` - A struct used to configure extra settings such as hardcoded **KEYS** and **SECRETS**, custom JSON error messages, Database settings (for `restgate.Database` mode) and context function. **PostgreSQL** users must set `Postgres` to true.

Settings
---------

If `AuthenticationSource==restgate.Database,` then **KEY** and **SECRET** fields in the `Config` struct represent the field names in the database table.

If you want to provide custom JSON error messages, you can pass something like this into the `Config` Struct:


```go
ErrorMessages: map[int]map[string]string{
			1:  map[string]string{"code": "1", "error": "No Key Or Secret"},
			2:  map[string]string{"code": "2", "error": "Unauthorized Access"},
			99: map[string]string{"code": "99", "error": "Software Developers have not setup authentication correctly"},
		}
```

Remember, if you want to modify the default error codes and messages, you must provide error messages for all 3. Don't change the number 1,2 and 99 on the far left hand side. They are for internal use.

It may be more useful to use the [`"github.com/pjebs/jsonerror"`](https://github.com/pjebs/jsonerror) package for setting custom error messages. See [`restgate.go@L86`](https://github.com/pjebs/restgate/blob/master/restgate.go#L86) for an example.


Debugging
---------

Set the `Debug` field to `true` in the `Config` struct. This will give extra details on why RestGate may not be set up correctly. Turn off `Debug` mode when your website is live.


FAQ
----

**How do I actually authenticate?**

When the user wants to use your API (i.e. send requests to your RestGate protected endpoints), they must modify the header of their request. They can't just use ordinary POST requests. For curl, the command is `-H.` [See this article](http://stackoverflow.com/questions/356705/how-to-send-a-header-using-a-http-request-through-a-curl-call).

For the code sample above, the HTTP Request Header will need to contain `X-Auth-Key: ***A valid Key goes here***` and `X-Auth-Secret: ***A valid Secret goes here***.`

If the Key/Secret is invalid, the user **will not** be able to access your endpoint. Instead they will be returned a JSON response: `Unauthorized Access` (provided you didn't customize the default error messages).

**Where should I put RestGate in my middleware stack?**

You should put it directly after Recovery, Logging and HTTPS Security middleware.

**How do I make this package even more secure?**

You MUST use middleware such as [Secure](https://github.com/unrolled/secure) to ensure all requests are via a HTTPS connection. Of course, the connection must also use a HTTPS connection, so purchase a [SSL certificate](http://www.rapidssl.com/).

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

Other Useful Packages
------------

Check out [`"github.com/pjebs/jsonerror"`](https://github.com/pjebs/jsonerror) package. It will make error-handling, debugging and diagnosis much simpler and more elegant for all your Go projects.


Check out [`"github.com/pjebs/optimus-go"`](https://github.com/pjebs/optimus-go) package. Internal ID hashing and Obfuscation using Knuth's Algorithm. (For databases etc)

Final Notes
------------

If you found this package useful, please **Star** it on github. Feel free to fork or provide pull requests. Any bug reports will be warmly received.


[PJ Engineering and Business Solutions Pty. Ltd.](http://www.pjebs.com.au)