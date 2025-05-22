package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

type Post struct {
	ID        int
	Author    string
	Content   string
	CreatedAt string
}

var db *sql.DB
var templates = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	log.Println("[DB] Connecting to SQLite database")
	var err error
	db, err = sql.Open("sqlite", "file:blog.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password TEXT
		);
		CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author TEXT,
			content TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[DB] Tables ensured OK")

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/create-post", createPostHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("[Server] Running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)

	rows, err := db.Query("SELECT id, author, content, created_at FROM posts ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Error loading posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Author, &post.Content, &post.CreatedAt)
		if err != nil {
			http.Error(w, "Error reading posts", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, "Error processing posts", http.StatusInternalServerError)
		return
	}

	err = templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Posts": posts,
		"User":  user,
	})
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
		if err != nil {
			http.Error(w, "Username already exists", 400)
			return
		}

		http.SetCookie(w, &http.Cookie{Name: "session", Value: username})
		http.Redirect(w, r, "/", 302)
		return
	}
	templates.ExecuteTemplate(w, "register.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		row := db.QueryRow("SELECT password FROM users WHERE username = ?", username)
		var pass string
		row.Scan(&pass)
		if pass != password {
			http.Error(w, "Invalid credentials", 400)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: username})
		http.Redirect(w, r, "/", 302)
		return
	}
	templates.ExecuteTemplate(w, "login.html", nil)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if r.Method == "POST" && r.FormValue("update_profile") == "true" {
		newUsername := r.FormValue("new_username")
		newPassword := r.FormValue("new_password")
		_, err := db.Exec("UPDATE users SET username = ?, password = ? WHERE username = ?", newUsername, newPassword, user)
		if err == nil {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: newUsername})
			user = newUsername
		}
	}

	rows, err := db.Query("SELECT content, created_at FROM posts WHERE author = ? ORDER BY created_at DESC", user)
	if err != nil {
		http.Error(w, "Error loading user posts", 500)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		rows.Scan(&post.Content, &post.CreatedAt)
		posts = append(posts, post)
	}

	templates.ExecuteTemplate(w, "profile.html", map[string]any{
		"Username": user,
		"Posts":    posts,
	})
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	if r.Method == "POST" {
		content := r.FormValue("content")
		if content != "" {
			_, err := db.Exec("INSERT INTO posts (author, content) VALUES (?, ?)", user, content)
			if err != nil {
				http.Error(w, "Error creating post", 500)
				return
			}
		}
		http.Redirect(w, r, "/profile", 302)
		return
	}
	http.Redirect(w, r, "/profile", 302)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/", 302)
}

func getUser(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
