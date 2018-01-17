package main

import (
  "os"
  "fmt"
	"log"
  "time"
	"net/http"
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

func getSession() *mgo.Session {
		host := "mongodb://" + l.Getenv("MONGODB_HOST", "localhost")
    s, err := mgo.Dial(host)
		log.Printf("host: %s", host)
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
  c := getSession().DB(l.Getenv("DATABASE", "recepies")).C("users")

  return func(w http.ResponseWriter, r *http.Request) {
    if (r.URL.Path != "/" || r.Method != "POST") {
      http.Error(w, "Not found", http.StatusNotFound)
      return
    }

    if err := r.ParseForm(); err != nil {
      fmt.Fprintf(w, "ParseForm() err: %v", err)
      return
    }

    u := r.FormValue("username")
    p := r.FormValue("password")

    user := new(User)

    if err := c.Find(bson.M{"u": u, "p": p}).One(&user); err != nil {
      http.Error(w, "Unauthorized", http.StatusForbidden)
      return
    }

    user.StandardClaims = standardClaims()

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, user)

    secret := []byte(os.Getenv("SECRET"))

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(secret)

    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    fmt.Fprintf(w, tokenString)
  }
}

func main() {
  port := ":" + l.Getenv("PORT", "3002")

  log.Printf("Server started on %s", port)

  http.HandleFunc("/", auth())

	log.Fatal(http.ListenAndServe(port, nil))
}
