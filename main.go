package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

type Profile struct {
	Status    string `json:"status"`
	BirthYear int    `json:"birth_year"`
	About     string `json:"about"`
	Photo     string `json:"photo,omitempty"`
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	var profile Profile
	err := db.QueryRow("SELECT status, birth_year, about FROM users WHERE id = 1").Scan(
		&profile.Status, &profile.BirthYear, &profile.About)
	if err != nil {
		json.NewEncoder(w).Encode(Response{false, "Error getting profile"})
		return
	}

	var photoData []byte
	err = db.QueryRow(
		"SELECT photo_data FROM user_photos WHERE user_id = 1 ORDER BY upload_date DESC LIMIT 1",
	).Scan(&photoData)
	if err == nil {
		profile.Photo = base64.StdEncoding.EncodeToString(photoData)
	}

	json.NewEncoder(w).Encode(struct {
		Response
		Profile Profile `json:"profile"`
	}{
		Response: Response{true, "Profile loaded"},
		Profile:  profile,
	})
}

func saveProfileHandler(w http.ResponseWriter, r *http.Request) {
	var profile Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec(
		"UPDATE users SET status = ?, birth_year = ?, about = ? WHERE id = 1",
		profile.Status, profile.BirthYear, profile.About,
	)
	if err != nil {
		json.NewEncoder(w).Encode(Response{false, "Error saving profile"})
		return
	}

	json.NewEncoder(w).Encode(Response{true, "Profile saved"})
}

func uploadPhotoHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	r.ParseMultipartForm(5 << 20) // 5MB limit
	photoData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(photoData) == 0 {
		json.NewEncoder(w).Encode(Response{false, "Empty file"})
		return
	}

	_, err = db.Exec(
		"INSERT INTO user_photos (user_id, photo_data) VALUES (?, ?)",
		1, photoData,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Response
		Photo string `json:"photo"`
	}{
		Response: Response{true, "Photo uploaded"},
		Photo:    base64.StdEncoding.EncodeToString(photoData),
	})
}

func initDB() {
	var err error
	if _, err = os.Stat("auth.db"); os.IsNotExist(err) {
		if _, err = os.Create("auth.db"); err != nil {
			log.Fatal(err)
		}
	}

	db, err = sql.Open("sqlite", "auth.db")
	if err != nil {
		log.Fatal(err)
	}

	sqlStmt := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		status TEXT,
		birth_year INTEGER,
		about TEXT
	);
	CREATE TABLE IF NOT EXISTS user_photos (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		photo_data BLOB NOT NULL,
		upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	if _, err = db.Exec(sqlStmt); err != nil {
		log.Fatal(err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
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

	_, err = db.Exec(
		"INSERT INTO users (username, password) VALUES (?, ?)",
		user.Username, string(hashedPassword),
	)
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
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var dbUser User
	err := db.QueryRow(
		"SELECT id, username, password FROM users WHERE username = ?",
		user.Username,
	).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password)

	if err != nil {
		status := http.StatusInternalServerError
		if err == sql.ErrNoRows {
			status = http.StatusUnauthorized
		}
		http.Error(w, "Invalid username or password", status)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Response
		Redirect string `json:"redirect"`
	}{
		Response: Response{true, "Login successful"},
		Redirect: "/profile.html",
	})
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()

	// API routes
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/profile", profileHandler).Methods("GET")
	r.HandleFunc("/api/save-profile", saveProfileHandler).Methods("POST")
	r.HandleFunc("/api/upload-photo", uploadPhotoHandler).Methods("POST")

	// Static files
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
