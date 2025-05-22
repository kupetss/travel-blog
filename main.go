package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strings"

	_ "modernc.org/sqlite"
)

type Post struct {
	ID        int
	Author    string
	Content   string
	CreatedAt string
}

type Comment struct {
	ID        int
	PostID    int
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
		CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER,
		author TEXT,
		content TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
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
	http.HandleFunc("/search", searchHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("[Server] Running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)

	// Обработка новой формы комментария
	if r.Method == "POST" && user != "" {
		postID := r.FormValue("post_id")
		content := r.FormValue("comment")
		if content != "" && postID != "" {
			_, err := db.Exec("INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)", postID, user, content)
			if err != nil {
				http.Error(w, "Error adding comment", 500)
				return
			}
		}
		http.Redirect(w, r, "/", 302)
		return
	}

	rows, err := db.Query("SELECT id, author, content, created_at FROM posts ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Error loading posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	postMap := map[int][]Comment{}

	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Author, &post.Content, &post.CreatedAt)
		if err != nil {
			http.Error(w, "Error reading posts", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	// Загрузка комментариев
	commentRows, err := db.Query("SELECT post_id, author, content, created_at FROM comments ORDER BY created_at ASC")
	if err != nil {
		http.Error(w, "Error loading comments", 500)
		return
	}
	defer commentRows.Close()

	for commentRows.Next() {
		var c Comment
		err := commentRows.Scan(&c.PostID, &c.Author, &c.Content, &c.CreatedAt)
		if err == nil {
			postMap[c.PostID] = append(postMap[c.PostID], c)
		}
	}

	err = templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Posts":    posts,
		"Comments": postMap,
		"User":     user,
	})
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)
	query := strings.TrimSpace(r.FormValue("query"))

	var posts []Post
	postMap := map[int][]Comment{}

	if query != "" {
		rows, err := db.Query("SELECT id, author, content, created_at FROM posts WHERE content LIKE ? OR author LIKE ? ORDER BY created_at DESC",
			"%"+query+"%", "%"+query+"%")
		if err != nil {
			http.Error(w, "Error searching posts", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var post Post
			err := rows.Scan(&post.ID, &post.Author, &post.Content, &post.CreatedAt)
			if err != nil {
				http.Error(w, "Error reading posts", http.StatusInternalServerError)
				return
			}
			posts = append(posts, post)
		}

		// Загрузка комментариев для найденных постов
		if len(posts) > 0 {
			var postIDs []interface{}
			for _, post := range posts {
				postIDs = append(postIDs, post.ID)
			}

			queryStr := "SELECT post_id, author, content, created_at FROM comments WHERE post_id IN (?" + strings.Repeat(",?", len(postIDs)-1) + ") ORDER BY created_at ASC"
			commentRows, err := db.Query(queryStr, postIDs...)
			if err != nil {
				http.Error(w, "Error loading comments", 500)
				return
			}
			defer commentRows.Close()

			for commentRows.Next() {
				var c Comment
				err := commentRows.Scan(&c.PostID, &c.Author, &c.Content, &c.CreatedAt)
				if err == nil {
					postMap[c.PostID] = append(postMap[c.PostID], c)
				}
			}
		}
	} else {
		http.Redirect(w, r, "/", 302)
		return
	}

	err := templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Posts":       posts,
		"Comments":    postMap,
		"User":        user,
		"SearchQuery": query,
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
