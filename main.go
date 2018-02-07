package main

import (
  "os"
  "fmt"
  "time"
	"net/http"
  "io/ioutil"
  "crypto/rsa"
  "crypto/sha512"
  "encoding/base64"
  "gopkg.in/mgo.v2"
  "gopkg.in/mgo.v2/bson"
  jwt "github.com/dgrijalva/jwt-go"
  l "github.com/eriklindqvist/recepies_api/app/lib"
  "github.com/eriklindqvist/recepies_auth/log"
)

type Scope struct {
  Entity string `json:"ent" bson:"e"`
  Actions []string `json:"act" bson:"a"`
}

type User struct {
    Username string `json:"usr" bson:"u"`
    Scopes []Scope `json:"scp" bson:"s"`
    jwt.StandardClaims
}

func getSession() *mgo.Session {
		host := "mongodb://" + l.Getenv("MONGODB_HOST", "localhost")
    s, err := mgo.Dial(host)
		log.Info(fmt.Sprintf("host: %s", host))
    // Check if connection error, is mongo running?
    if err != nil {
        log.Err(fmt.Sprintf("Mongo: %s", err))
        os.Exit(1)
    }
    return s
}

func standardClaims() jwt.StandardClaims {
  return jwt.StandardClaims{
      IssuedAt: time.Now().Unix(),
  }
}

func auth() http.HandlerFunc {
  var (
    pem []byte
    privateKey *rsa.PrivateKey
    err error
  )

  c := getSession().DB(l.Getenv("DATABASE", "recepies")).C("users")

  if pem, err = ioutil.ReadFile(l.Getenv("KEYFILE", "private.rsa")); err != nil {
    log.Panic(err.Error())
  }

  if privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(pem); err != nil {
    log.Panic(err.Error())
  }

  return func(w http.ResponseWriter, r *http.Request) {
    if (r.URL.Path != "/" || r.Method != "POST") {
      log.Err(fmt.Sprintf("%s %s 404 Not Found", r.Method, r.URL.Path))
      http.Error(w, "Not found", http.StatusNotFound)
      return
    } else {
      log.Info(fmt.Sprintf("%s %s 200 OK", r.Method, r.URL.Path))
    }

    if err := r.ParseForm(); err != nil {
      log.Err(fmt.Sprintf("ParseForm() err: %v", err))
      http.Error(w, "Internal Server Error", http.StatusInternalServerError)
      return
    }

    u := r.FormValue("username")
    p := r.FormValue("password")

    hash := sha512.Sum512_256([]byte(p))
    pass := base64.URLEncoding.EncodeToString(hash[:])

    user := new(User)

    if err := c.Find(bson.M{"u": u, "p": pass}).One(&user); err != nil {
      log.Err(fmt.Sprintf("Unauthorized user: %s", u))
      http.Error(w, "Unauthorized", http.StatusForbidden)
      return
    }

    log.Info(fmt.Sprintf("Authorized user: %s", user.Username))

    user.StandardClaims = standardClaims()

    token := jwt.NewWithClaims(jwt.SigningMethodRS512, user)

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(privateKey)

    if err != nil {
      log.Err(fmt.Sprintf("Could not sign token: %s", err.Error()))
      http.Error(w, "Internal Server Error", http.StatusInternalServerError)
      return
    }

    fmt.Fprintf(w, tokenString)
  }
}

func main() {
  log.Info("Server started")

  http.HandleFunc("/", auth())

	if err := http.ListenAndServe(":3002", nil); err != nil {
    log.Err(err.Error())
  }

  os.Exit(0)
}
