package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	JWTSecret   = "your_very_strong_secret_key_123!"
	TokenExpire = 24 * time.Hour
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

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWTSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func initDB() {
	var err error
	dbPath := "auth.db"

	if _, err = os.Stat(dbPath); os.IsNotExist(err) {
		file, err := os.Create(dbPath)
		if err != nil {
			log.Fatal("Failed to create database file:", err)
		}
		file.Close()
	}

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		status TEXT DEFAULT '',
		birth_year INTEGER DEFAULT 0,
		about TEXT DEFAULT ''
	);
	
	CREATE TABLE IF NOT EXISTS user_photos (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		photo_data BLOB NOT NULL,
		upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`)

	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(user.Username) < 4 || len(user.Password) < 6 {
		json.NewEncoder(w).Encode(Response{false, "Username must be at least 4 chars and password 6 chars"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
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
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Response{true, "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var dbUser User
	err := db.QueryRow(
		"SELECT id, username, password FROM users WHERE username = ?",
		user.Username,
	).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	claims := &Claims{
		UserID: dbUser.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenExpire)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWTSecret))
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Response
		Token    string `json:"token"`
		UserID   int    `json:"user_id"`
		Redirect string `json:"redirect"`
	}{
		Response: Response{true, "Login successful"},
		Token:    tokenString,
		UserID:   dbUser.ID,
		Redirect: "/profile.html",
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var profile Profile
	err := db.QueryRow(
		"SELECT status, birth_year, about FROM users WHERE id = ?",
		claims.UserID,
	).Scan(&profile.Status, &profile.BirthYear, &profile.About)

	if err != nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	var photoData []byte
	err = db.QueryRow(
		"SELECT photo_data FROM user_photos WHERE user_id = ? ORDER BY upload_date DESC LIMIT 1",
		claims.UserID,
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
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var profile Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(
		"UPDATE users SET status = ?, birth_year = ?, about = ? WHERE id = ?",
		profile.Status, profile.BirthYear, profile.About, claims.UserID,
	)

	if err != nil {
		http.Error(w, "Failed to save profile", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Response{true, "Profile saved successfully"})
}

func uploadPhotoHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	file, _, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, "No photo uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Ограничиваем размер файла 5MB
	r.ParseMultipartForm(5 << 20)
	photoData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read photo", http.StatusInternalServerError)
		return
	}

	if len(photoData) == 0 {
		http.Error(w, "Empty photo", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(
		"INSERT INTO user_photos (user_id, photo_data) VALUES (?, ?)",
		claims.UserID, photoData,
	)

	if err != nil {
		http.Error(w, "Failed to save photo", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Response
		Photo string `json:"photo"`
	}{
		Response: Response{true, "Photo uploaded successfully"},
		Photo:    base64.StdEncoding.EncodeToString(photoData),
	})
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()

	// API routes
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/profile", authMiddleware(profileHandler)).Methods("GET")
	r.HandleFunc("/api/save-profile", authMiddleware(saveProfileHandler)).Methods("POST")
	r.HandleFunc("/api/upload-photo", authMiddleware(uploadPhotoHandler)).Methods("POST")

	// Static files
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	port := "8080"
	fmt.Printf("Server running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
