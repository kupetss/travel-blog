package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB
var tmpl *template.Template
var store = sessions.NewCookieStore([]byte("your-secret-key"))

type User struct {
	ID       int
	Username string
	Password string
	Age      int
	About    string
	Avatar   string
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
			password TEXT,
			age INTEGER,
			about TEXT,
			avatar TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func initTemplates() {
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, username, age, about, avatar FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Age, &user.About, &user.Avatar)
	if err != nil {
		http.Error(w, "Ошибка загрузки профиля", http.StatusInternalServerError)
		return
	}

	tmpl.ExecuteTemplate(w, "home.html", user)
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	username := getUsernameFromSession(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	age := r.FormValue("age")
	about := r.FormValue("about")

	_, err := db.Exec("UPDATE users SET age = ?, about = ? WHERE username = ?", age, about, username)
	if err != nil {
		http.Error(w, "Ошибка обновления профиля", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func uploadAvatarHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	username := getUsernameFromSession(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var oldAvatar string
	err := db.QueryRow("SELECT avatar FROM users WHERE username = ?", username).Scan(&oldAvatar)
	if err != nil {
		http.Error(w, "Ошибка получения текущего аватара", http.StatusInternalServerError)
		return
	}

	r.ParseMultipartForm(5 << 20)

	file, handler, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "Ошибка загрузки файла", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buff := make([]byte, 512)
	if _, err = file.Read(buff); err != nil {
		http.Error(w, "Ошибка чтения файла", http.StatusInternalServerError)
		return
	}
	file.Seek(0, 0)

	if !strings.HasPrefix(http.DetectContentType(buff), "image/") {
		http.Error(w, "Файл должен быть изображением", http.StatusBadRequest)
		return
	}

	ext := filepath.Ext(handler.Filename)
	newFilename := fmt.Sprintf("%s%s", uuid.New().String(), ext)
	avatarPath := filepath.Join("uploads", "avatars", newFilename)

	f, err := os.Create(avatarPath)
	if err != nil {
		http.Error(w, "Не удалось сохранить файл", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err = io.Copy(f, file); err != nil {
		http.Error(w, "Ошибка сохранения файла", http.StatusInternalServerError)
		return
	}

	if oldAvatar != "" {
		oldPath := strings.TrimPrefix(oldAvatar, "/")
		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Remove(oldPath); err != nil {
				log.Printf("Не удалось удалить старый аватар: %v", err)
			}
		}
	}

	webPath := "/" + avatarPath
	_, err = db.Exec("UPDATE users SET avatar = ? WHERE username = ?", webPath, username)
	if err != nil {
		http.Error(w, "Ошибка обновления профиля", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	_, err = db.Exec("INSERT INTO users (username, password, age, about, avatar) VALUES (?, ?, 0, '', '')",
		username, hashedPassword)
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

func main() {
	initDB()
	initTemplates()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/update-profile", updateProfileHandler)
	http.HandleFunc("/upload-avatar", uploadAvatarHandler)

	fs := http.FileServer(http.Dir("."))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", fs))

	if err := os.MkdirAll("uploads/avatars", 0755); err != nil {
		log.Fatal("Не удалось создать папку для загрузок: ", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server started on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
