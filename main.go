package main

import (
  "os"
  "fmt"
	"io"
  "time"
	"net/http"
  "io/ioutil"
  "crypto/rsa"
  "crypto/sha512"
  "encoding/base64"
  "gopkg.in/mgo.v2"
  "gopkg.in/mgo.v2/bson"
  jwt "github.com/dgrijalva/jwt-go"
  l "github.com/eriklindqvist/recepies/app/lib"
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

func stderr(message string) {
  print(os.Stderr, message)
}

func stderrf(format string, a ...interface{}) {
  print(os.Stderr, fmt.Sprintf(format, a))
}

func stdout(message string) {
  print(os.Stdout, message)
}

func stdoutf(format string, a ...interface{}) {
  print(os.Stdout, fmt.Sprintf(format, a))
}

func print(w io.Writer, message string) {
  fmt.Fprintf(w, "%s\n", message)
}

func getSession() *mgo.Session {
		host := "mongodb://" + l.Getenv("MONGODB_HOST", "localhost")
    s, err := mgo.Dial(host)
		stdoutf("host: %s", host)
    // Check if connection error, is mongo running?
    if err != nil {
        panic(err)
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
    stderr(err.Error())
    os.Exit(1)
  }

  if privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(pem); err != nil {
    stderr(err.Error())
    os.Exit(1)
  }

  return func(w http.ResponseWriter, r *http.Request) {
    if (r.URL.Path != "/" || r.Method != "POST") {
      http.Error(w, "Not found", http.StatusNotFound)
      return
    }

    if err := r.ParseForm(); err != nil {
      stderrf("ParseForm() err: %v", err)
      http.Error(w, "Internal Server Error", http.StatusInternalServerError)
      return
    }

    u := r.FormValue("username")
    p := r.FormValue("password")

    hash := sha512.Sum512_256([]byte(p))
    pass := base64.URLEncoding.EncodeToString(hash[:])

    stdout(pass)

    user := new(User)

    if err := c.Find(bson.M{"u": u, "p": pass}).One(&user); err != nil {
      http.Error(w, "Unauthorized", http.StatusForbidden)
      return
    }

    stdoutf("Authorized user: %s", user.Username)

    user.StandardClaims = standardClaims()

    token := jwt.NewWithClaims(jwt.SigningMethodRS512, user)

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(privateKey)

    if err != nil {
      stderr(err.Error())
      http.Error(w, "Internal Server Error", http.StatusInternalServerError)
      return
    }

    fmt.Fprintf(w, tokenString)
  }
}

func main() {
  stdout("Server started")

  http.HandleFunc("/", auth())

	http.ListenAndServe(":3002", nil)
}
