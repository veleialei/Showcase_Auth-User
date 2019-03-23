package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		//response with error
		error.Message = "Email is mising"
		//send status bad request
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		//response with error
		//send status bad request
		error.Message = "Passworc is mising"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)

	stmt := "insert into users (email, password, firstname, lastname) values($1, $2, $3, $4) RETURNING id;"

	err = db.QueryRow(stmt, user.Email, user.Password, user.FirstName, user.LastName).Scan(&user.ID)

	if err != nil {
		error.Message = "Server error."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	user.Password = ""

	w.Header().Set("Content-Type", "application/json")

	responseJSON(w, user)
}

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"id":    user.ID,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Emial is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password

	row := db.QueryRow("select * from users where email = $1", user.Email)

	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		}
		log.Fatal(err)
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		error.Message = "Invalid Password"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	token, err := GenerateToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)

	jwt.Token = token

	responseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked.")
}

//function , input token out put user id
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 || len(bearerToken) == 1 {
			authToken := bearerToken[len(bearerToken)-1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("secret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				responseJSON(w, token.Claims)
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}

func main() {
	pgUrl, err := pq.ParseURL("postgres://rrffuqac:mEmowyG0O-9JoVKMVhHA40HzUKtHx11K@isilo.db.elephantsql.com:5432/rrffuqac")
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
