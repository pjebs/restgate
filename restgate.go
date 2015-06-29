package restgate

/*
|--------------------------------------------------------------------------
| WARNING
|--------------------------------------------------------------------------
| Always use this middleware library with a HTTPS Connection.
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
	"crypto/subtle"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	e "github.com/pjebs/jsonerror"
	"gopkg.in/unrolled/render.v1"
)

type AuthenticationSource int

const (
	Static   AuthenticationSource = 0
	Database                      = 1
)

//When AuthenticationSource=Static, Key(s)=Actual Key and Secret(s)=Actual Secret.
//When AuthenticationSource=Database, Key[0]=Key_Column and Secret[0]=Secret_Column.
type Config struct {
	*sql.DB
	Key           []string
	Secret        []string //Can be "" but not recommended
	TableName     string
	ErrorMessages map[int]map[string]string
	Context       func(r *http.Request, authenticatedKey string)
	Debug         bool
	Postgres      bool
}

type RESTGate struct {
	headerKeyLabel    string
	headerSecretLabel string
	source            AuthenticationSource
	config            Config
}

func New(headerKeyLabel string, headerSecretLabel string, as AuthenticationSource, config Config) *RESTGate {
	t := &RESTGate{headerKeyLabel: headerKeyLabel, headerSecretLabel: headerSecretLabel, source: as, config: config}
	log.Printf("RestGate initializing")

	numberKeys := len(t.config.Key)
	numberSecrets := len(t.config.Secret)

	if numberKeys == 0 { //Key is not set
		if t.config.Debug == true {
			log.Printf("RestGate: Key is not set")
		}
		return nil
	}

	if numberSecrets > numberKeys { //Too many Secret's defined
		if t.config.Debug == true {
			log.Printf("RestGate: Too many Secrets defined. At most there should be 1 secret per key")
		}
		return nil
	}

	if headerKeyLabel == "" { //headerKeyLabel must be defined
		if t.config.Debug == true {
			log.Printf("RestGate: headerKeyLabel is not defined.")
		}
		return nil
	}

	//Default Error Messages
	if t.config.ErrorMessages == nil {
		t.config.ErrorMessages = map[int]map[string]string{
			1:  e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render(),
			2:  e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render(),
			99: e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render(),
		}
	}

	if as == Database {

		if numberKeys != 1 { //We need exactly 1 Key (it represents field name in database)
			if t.config.Debug == true {
				log.Printf("RestGate: For Database mode, we need exactly 1 Key which represents the field name in the database table")
			}
			return nil
		}

		//Check if database is set.
		//The developer should ensure a database has been selected (i.e. to prevent "No Database selected" error)
		if t.config.DB == nil { //DB is not set
			if t.config.Debug == true {
				log.Printf("RestGate: Database is not set. Be sure that a database name is selected")
			}
			return nil
		}

		//Check if table is set
		if t.config.TableName == "" { //Table name is not set
			if t.config.Debug == true {
				log.Printf("RestGate: For Database mode, a table name is required")
			}
			return nil
		}

	}

	return t
}

func (self *RESTGate) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

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
			if secureCompare(element, key) { //Key matches

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
		} else { //Authentication PASSED
			if self.config.Context != nil {
				self.config.Context(req, key)
			}
			next(w, req)
		}

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
				log.Printf("RestGate: Run time database error: %+v", err)
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

		// log.Printf("result error: %+v", err)
		// log.Printf("count: %+v", count)

		if err == nil && count == 1 {
			//Authentication PASSED
			if self.config.Context != nil {
				self.config.Context(req, key)
			}
			next(w, req)
		} else { //==sql.ErrNoRows or count == 0
			//Something went wrong
			if self.config.Debug == true && count > 1 {
				log.Printf("RestGate: Database query returned more than 1 identical Key. Make sure the KEY field in the table is set to UNIQUE")
			}
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
			return
		}

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
	} else {
		/* Securely compare actual to itself to keep constant time, but always return false */
		return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false
	}
}
