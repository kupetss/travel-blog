package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func initDB() {
	var err error
	if _, err := os.Stat("auth.db"); os.IsNotExist(err) {
		os.Create("auth.db")
	}

	db, err = sql.Open("sqlite", "auth.db")
	if err != nil {
		log.Fatal(err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(user.Username) < 4 || len(user.Password) < 6 {
		json.NewEncoder(w).Encode(Response{false, "Username must be at least 4 chars and password 6 chars"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, string(hashedPassword))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			json.NewEncoder(w).Encode(Response{false, "Username already exists"})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Response{true, "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var dbUser User
	row := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", user.Username)
	err = row.Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{false, "Invalid username or password"})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password))
	if err != nil {
		json.NewEncoder(w).Encode(Response{false, "Invalid username or password"})
		return
	}

	json.NewEncoder(w).Encode(Response{true, "Login successful"})
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()

	// API routes
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")

	// Serve static files
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./static"))))

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
