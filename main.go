package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var db *sql.DB
var tmpl *template.Template
var store = sessions.NewCookieStore([]byte("your-secret-key"))

// Определение структуры User
type User struct {
	ID       int
	Username string
	Password string
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func initTemplates() {
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	initDB()
	initTemplates()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl.ExecuteTemplate(w, "home.html", username)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["username"] = username
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["username"] = nil
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func getUsernameFromSession(r *http.Request) string {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok {
		return ""
	}
	return username
}
