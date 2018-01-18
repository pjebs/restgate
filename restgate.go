package restgate

/*
|--------------------------------------------------------------------------
| WARNING
|--------------------------------------------------------------------------
| Never Set HTTPSProtectionOff=true In Production.
| The Key and Password will be exposed and highly unsecure otherwise!
| The database server should also use HTTPS Connection and be hidden away
|
*/

/*
Thanks to Ido Ben-Natan ("IdoBn") for postgres fix.
Thanks to Jeremy Saenz & Brendon Murphy for timing-attack protection
*/

import (
	// "errors"

	"crypto/rsa"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	e "github.com/pjebs/jsonerror"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
	"gopkg.in/unrolled/render.v1"
)

type AuthenticationSource int

const (
	Static   AuthenticationSource = 0
	Database                      = 1
	JWT                           = 2
)

//JWT supported signing methods
const (
	RSA = iota
	HMAC
)

var rsaPubKey *rsa.PublicKey

//When AuthenticationSource=Static, Key(s)=Actual Key and Secret(s)=Actual Secret.
//When AuthenticationSource=Database, Key[0]=Key_Column and Secret[0]=Secret_Column.
//When AuthenticationSource=JWT, Key and Secret are not required.
type Config struct {
	*sql.DB
	Key                     []string
	Secret                  []string //Can be "" but not recommended
	TableName               string
	JWT                     JWTConfig
	ErrorMessages           map[int]map[string]string
	Context                 func(r *http.Request, authenticatedKey string)
	Debug                   bool
	Postgres                bool
	Logger                  ALogger
	HTTPSProtectionOff      bool //Default is HTTPS Protection On
	GAE_FlexibleEnvironment bool //Default is false. ALWAYS KEEP THIS FALSE UNLESS you are using Google App Engine-Flexible Environment
}

type JWTConfig struct {
	Algorithm        int               //What Algorithm our tokens are signed with (restgate.RSA or restgate.HMAC)
	SigningMethod    jwt.SigningMethod //The jwt signing method expected for incoming tokens, for example: jwt.SigningMethodHS256
	RSAPublicKeyData []byte            //RSA public key data only used if Algorithm is set to restgate.RSA
	HMACSecret       string            //HMAC secret only used if Algorithm is set to restgate.HMAC
	Claims           func(r *http.Request, name string, value interface{})
}

type RESTGate struct {
	headerKeyLabel    string
	headerSecretLabel string
	source            AuthenticationSource
	config            Config
}

type ALogger interface {
	Printf(format string, v ...interface{})
}

func New(headerKeyLabel string, headerSecretLabel string, as AuthenticationSource, config Config) *RESTGate {
	if config.Logger == nil {
		config.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	t := &RESTGate{headerKeyLabel: headerKeyLabel, headerSecretLabel: headerSecretLabel, source: as, config: config}
	t.config.Logger.Printf("RestGate initializing")

	numberKeys := len(t.config.Key)
	numberSecrets := len(t.config.Secret)

	if numberKeys == 0 && as != JWT { //Key is not set
		if t.config.Debug == true {
			t.config.Logger.Printf("RestGate: Key is not set")
		}
		return nil
	}

	if numberSecrets > numberKeys { //Too many Secret's defined
		if t.config.Debug == true {
			t.config.Logger.Printf("RestGate: Too many Secrets defined. At most there should be 1 secret per key")
		}
		return nil
	}

	if headerKeyLabel == "" { //headerKeyLabel must be defined
		if t.config.Debug == true {
			t.config.Logger.Printf("RestGate: headerKeyLabel is not defined.")
		}
		return nil
	}

	//Default Error Messages
	if t.config.ErrorMessages == nil {
		t.config.ErrorMessages = map[int]map[string]string{
			1:  e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render(),
			2:  e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render(),
			3:  e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render(),
			99: e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render(),
		}
	} else {
		if _, ok := t.config.ErrorMessages[1]; !ok {
			t.config.ErrorMessages[1] = e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[2]; !ok {
			t.config.ErrorMessages[2] = e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[3]; !ok {
			t.config.ErrorMessages[3] = e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[99]; !ok {
			t.config.ErrorMessages[99] = e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render()
		}
	}

	//Check if HTTPS Protection has been turned off
	if t.config.HTTPSProtectionOff {
		//HTTPS Protection is off
		t.config.Logger.Printf("\x1b[31mWARNING: HTTPS Protection is off. This is potentially insecure!\x1b[39;49m")
	}

	if t.config.GAE_FlexibleEnvironment {
		//HTTPS Protection is off
		t.config.Logger.Printf("\x1b[31mWARNING: Set GAE_FlexibleEnvironment to false UNLESS you are using Google App Engine-Flexible Environment. This is potentially insecure!\x1b[39;49m")
	}

	if as == Database {

		if numberKeys != 1 { //We need exactly 1 Key (it represents field name in database)
			if t.config.Debug == true {
				t.config.Logger.Printf("RestGate: For Database mode, we need exactly 1 Key which represents the field name in the database table")
			}
			return nil
		}

		//Check if database is set.
		//The developer should ensure a database has been selected (i.e. to prevent "No Database selected" error)
		if t.config.DB == nil { //DB is not set
			if t.config.Debug == true {
				t.config.Logger.Printf("RestGate: Database is not set. Be sure that a database name is selected")
			}
			return nil
		}

		//Check if table is set
		if t.config.TableName == "" { //Table name is not set
			if t.config.Debug == true {
				t.config.Logger.Printf("RestGate: For Database mode, a table name is required")
			}
			return nil
		}

	}

	if as == JWT {

		var err error

		switch t.config.JWT.Algorithm {
		// Validate that the key is a valid RSA public key
		case RSA:
			rsaPubKey, err = jwt.ParseRSAPublicKeyFromPEM(t.config.JWT.RSAPublicKeyData)
			if err != nil {
				if t.config.Debug == true {
					t.config.Logger.Printf("RestGate: RSA Public key data is invalid: %+v", err)
				}
				return nil
			}
		// Validate that we have a valid secret
		case HMAC:
			if t.config.JWT.HMACSecret == "" {
				if t.config.Debug == true {
					t.config.Logger.Printf("RestGate: HMAC algorithm selected but no secret was configured")
				}
				return nil
			}

		}

	}

	return t
}

func (self *RESTGate) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	//Check if HTTPS Protection has been turned off
	if !self.config.HTTPSProtectionOff {
		//HTTPS Protection is on so we must check it

		if self.config.GAE_FlexibleEnvironment == true {
			if req.Header.Get("X-AppEngine-Https") != "on" {
				r := render.New(render.Options{})
				r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[3]) //"Please use HTTPS connection"
				return
			}
		} else {
			if !(strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil) {
				r := render.New(render.Options{})
				r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[3]) //"Please use HTTPS connection"
				return
			}
		}
	}

	//Check key in Header
	key := req.Header.Get(self.headerKeyLabel)
	secret := req.Header.Get(self.headerSecretLabel)

	if key == "" {
		//Authentication Information not included in request
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[1]) //"No Key Or Secret"
		return
	}

	if self.source == Static {

		secretDoesntExist := len(self.config.Secret) == 0
		authenticationPassed := false

		//First search through all keys
		for index, element := range self.config.Key {
			if secureCompare(key, element) { //Key matches

				//Now check if secret matches
				if secretDoesntExist {
					//Authentication PASSED
					authenticationPassed = true
					break
				} else if index > (len(self.config.Secret) - 1) { //Out of Range so corresponding secret doesn't exist
					//Authentication PASSED
					authenticationPassed = true
					break
				} else {
					//Corresponding Secret exists
					if secureCompare(secret, self.config.Secret[index]) {
						//Authentication PASSED
						authenticationPassed = true
						break
					} else {
						//Authentication FAILED
						authenticationPassed = false
						break
					}
				}
			}
		}

		//Authentication FAILED - No Key's matched
		if authenticationPassed == false {
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
			return
		}
		//Authentication PASSED
		if self.config.Context != nil {
			self.config.Context(req, key)
		}
		next(w, req)

	} else if self.source == Database {
		db := self.config.DB

		secretDoesntExists := len(self.config.Secret) == 0 || self.config.Secret[0] == ""

		var preparedStatement string
		if secretDoesntExists {
			if self.config.Postgres == false { //COUNT(*) is definately faster on MYISAM and possibly InnoDB (MySQL engines)
				preparedStatement = fmt.Sprintf("SELECT COUNT(*) FROM `%v` WHERE `%v`=?", self.config.TableName, self.config.Key[0])
			} else {
				preparedStatement = fmt.Sprintf("SELECT COUNT(%v) FROM %v WHERE %v=$1", self.config.Key[0], self.config.TableName, self.config.Key[0])
			}
		} else {
			if self.config.Postgres == false {
				preparedStatement = fmt.Sprintf("SELECT COUNT(*) FROM `%v` WHERE `%v`=? AND `%v`=?", self.config.TableName, self.config.Key[0], self.config.Secret[0])
			} else {
				preparedStatement = fmt.Sprintf("SELECT COUNT(%v) FROM %v WHERE %v=$1 AND %v=$2", self.config.Key[0], self.config.TableName, self.config.Key[0], self.config.Secret[0])
			}
		}

		stmt, err := db.Prepare(preparedStatement)
		if err != nil {
			if self.config.Debug == true {
				self.config.Logger.Printf("RestGate: Run time database error: %+v", err)
			}
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[99]) //"Software Developers have not setup authentication correctly"
			return
		}
		defer stmt.Close()

		var count int //stores query result
		if secretDoesntExists {
			err = stmt.QueryRow(key).Scan(&count)
		} else {
			err = stmt.QueryRow(key, secret).Scan(&count)
		}

		// t.config.Logger.Printf("result error: %+v", err)
		// t.config.Logger.Printf("count: %+v", count)

		if err == nil && count == 1 {
			//Authentication PASSED
			if self.config.Context != nil {
				self.config.Context(req, key)
			}
			next(w, req)
		} else { //==sql.ErrNoRows or count == 0
			//Something went wrong
			if self.config.Debug == true && count > 1 {
				self.config.Logger.Printf("RestGate: Database query returned more than 1 identical Key. Make sure the KEY field in the table is set to UNIQUE")
			}
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
			return
		}

	} else if self.source == JWT {

		var jwtKey interface{}
		var jwtToken string

		// See what type of Signing method we need to verify against
		// For RSA signed tokens we need the RSA public key
		// For HMAC signed tokens we just need the secret

		if self.config.JWT.Algorithm == RSA {
			jwtKey = rsaPubKey
		} else if self.config.JWT.Algorithm == HMAC {
			jwtKey = []byte(self.config.JWT.HMACSecret)
		} else {
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[99]) //"Software Developers have not setup authentication correctly"
			return
		}

		// Remove the "Bearer" authorization type from the key if exists to get just the token data
		if strings.Contains(key, "Bearer ") {
			jwtToken = strings.TrimPrefix(key, "Bearer ")
		} else {
			jwtToken = key
		}

		//Validate token and get the claims if any
		claims, err := verifyToken(jwtToken, self.config.JWT.SigningMethod, jwtKey)
		if err != nil {
			if self.config.Debug == true {
				self.config.Logger.Printf("RestGate: JWT validation error: %+v", err)
			}
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
			return
		}

		if self.config.Context != nil {
			self.config.Context(req, key)
		}

		// Add claims to the context if we got any
		if self.config.JWT.Claims != nil && len(claims) > 0 {
			for k, v := range claims {
				self.config.JWT.Claims(req, k, v)
			}
		}
		next(w, req)

	} else {
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[99]) //"Software Developers have not setup authentication correctly"
		return
	}

}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	}
	/* Securely compare actual to itself to keep constant time, but always return false */
	return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false

}

//verifyToken does the actual validation of the token using the configured signing method
func verifyToken(tokenData string, signMethod jwt.SigningMethod, key interface{}) (map[string]interface{}, error) {

	var token *jwt.Token
	var tokenClaims jwt.MapClaims
	var err error

	token, err = jwt.Parse(tokenData, func(token *jwt.Token) (interface{}, error) {
		if token.Method != signMethod {
			return nil, fmt.Errorf("unexpected signing method on token: %v (was expecting: %s)", token.Header["alg"], signMethod.Alg())
		}
		tokenClaims = token.Claims.(jwt.MapClaims)
		return key, nil
	})

	if err == nil && token.Valid {
		return tokenClaims, nil
	}
	return tokenClaims, err
}
