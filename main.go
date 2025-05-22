package main

import (
	"database/sql"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Post struct {
	ID        int
	Author    string
	Content   string
	ImagePath string
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
	log.Println("[DB] Initializing database...")
	initDatabase()
	defer db.Close()

	log.Println("[Server] Starting HTTP server...")
	startServer()
}

func initDatabase() {
	var err error
	db, err = sql.Open("sqlite", "file:blog.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Проверяем соединение
	if err = db.Ping(); err != nil {
		log.Fatal("Database connection failed:", err)
	}

	// Удаляем старые таблицы (для разработки)
	_, _ = db.Exec("DROP TABLE IF EXISTS comments")
	_, _ = db.Exec("DROP TABLE IF EXISTS posts")
	_, _ = db.Exec("DROP TABLE IF EXISTS users")

	// Создаем новые таблицы с правильной структурой
	createTables()
	verifyDatabaseStructure()
}

func createTables() {
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		author TEXT NOT NULL,
		content TEXT NOT NULL,
		image_path TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (author) REFERENCES users(username)
	);
	
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER NOT NULL,
		author TEXT NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
		FOREIGN KEY (author) REFERENCES users(username)
	);
	`

	if _, err := db.Exec(sqlStmt); err != nil {
		log.Fatal("Failed to create tables:", err)
	}
	log.Println("[DB] Tables created successfully")
}

func verifyDatabaseStructure() {
	requiredColumns := map[string][]string{
		"posts":    {"id", "author", "content", "image_path", "created_at"},
		"comments": {"id", "post_id", "author", "content", "created_at"},
		"users":    {"id", "username", "password"},
	}

	for table, columns := range requiredColumns {
		for _, column := range columns {
			var exists int
			err := db.QueryRow(
				"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?",
				table, column,
			).Scan(&exists)

			if err != nil || exists == 0 {
				log.Fatalf("Database structure error: column %s.%s is missing", table, column)
			}
		}
	}
	log.Println("[DB] Database structure verified")
}

func startServer() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/create-post", createPostHandler)
	http.HandleFunc("/search", searchHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Создаем папку для загрузок
	if err := os.MkdirAll("static/uploads", 0755); err != nil {
		log.Fatal("Failed to create uploads directory:", err)
	}

	log.Println("[Server] Running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)

	if r.Method == "POST" && user != "" {
		handleCommentSubmission(w, r, user)
		return
	}

	posts, postMap, err := getPostsWithComments()
	if err != nil {
		log.Println("Error getting posts:", err)
		http.Error(w, "Error loading content", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "index.html", map[string]interface{}{
		"Posts":    posts,
		"Comments": postMap,
		"User":     user,
	})
}

func handleCommentSubmission(w http.ResponseWriter, r *http.Request, user string) {
	postID := r.FormValue("post_id")
	content := r.FormValue("comment")
	if content == "" || postID == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if _, err := db.Exec(
		"INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)",
		postID, user, content,
	); err != nil {
		log.Println("Error adding comment:", err)
		http.Error(w, "Error adding comment", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func getPostsWithComments() ([]Post, map[int][]Comment, error) {
	posts, err := getPosts()
	if err != nil {
		return nil, nil, err
	}

	comments, err := getComments()
	if err != nil {
		return nil, nil, err
	}

	postMap := make(map[int][]Comment)
	for _, c := range comments {
		postMap[c.PostID] = append(postMap[c.PostID], c)
	}

	return posts, postMap, nil
}

func getPosts() ([]Post, error) {
	rows, err := db.Query(`
		SELECT id, author, content, image_path, created_at 
		FROM posts 
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(
			&post.ID, &post.Author, &post.Content,
			&post.ImagePath, &post.CreatedAt,
		); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	return posts, rows.Err()
}

func getComments() ([]Comment, error) {
	rows, err := db.Query(`
		SELECT id, post_id, author, content, created_at 
		FROM comments 
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(
			&c.ID, &c.PostID, &c.Author,
			&c.Content, &c.CreatedAt,
		); err != nil {
			return nil, err
		}
		comments = append(comments, c)
	}
	return comments, rows.Err()
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	if err := templates.ExecuteTemplate(w, tmpl, data); err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)
	query := strings.TrimSpace(r.FormValue("query"))

	var posts []Post
	postMap := map[int][]Comment{}

	if query != "" {
		rows, err := db.Query("SELECT id, author, content, image_path, created_at FROM posts WHERE content LIKE ? OR author LIKE ? ORDER BY created_at DESC",
			"%"+query+"%", "%"+query+"%")
		if err != nil {
			http.Error(w, "Error searching posts", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var post Post
			err := rows.Scan(&post.ID, &post.Author, &post.Content, &post.ImagePath, &post.CreatedAt)
			if err != nil {
				http.Error(w, "Error reading posts", http.StatusInternalServerError)
				return
			}
			posts = append(posts, post)
		}

		if len(posts) > 0 {
			var postIDs []interface{}
			for _, post := range posts {
				postIDs = append(postIDs, post.ID)
			}

			queryStr := "SELECT id, post_id, author, content, created_at FROM comments WHERE post_id IN (?" + strings.Repeat(",?", len(postIDs)-1) + ") ORDER BY created_at ASC"
			commentRows, err := db.Query(queryStr, postIDs...)
			if err != nil {
				http.Error(w, "Error loading comments", 500)
				return
			}
			defer commentRows.Close()

			for commentRows.Next() {
				var c Comment
				err := commentRows.Scan(&c.ID, &c.PostID, &c.Author, &c.Content, &c.CreatedAt)
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

	rows, err := db.Query("SELECT id, content, image_path, created_at FROM posts WHERE author = ? ORDER BY created_at DESC", user)
	if err != nil {
		http.Error(w, "Error loading user posts", 500)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		rows.Scan(&post.ID, &post.Content, &post.ImagePath, &post.CreatedAt)
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
		err := r.ParseMultipartForm(10 << 20) // 10 MB max
		if err != nil {
			http.Error(w, "File too large", http.StatusBadRequest)
			return
		}

		content := r.FormValue("content")
		if content == "" {
			http.Error(w, "Content is required", http.StatusBadRequest)
			return
		}

		var imagePath string
		file, handler, err := r.FormFile("image")
		if err == nil {
			defer file.Close()

			if _, err := os.Stat("static/uploads"); os.IsNotExist(err) {
				os.MkdirAll("static/uploads", 0755)
			}

			imagePath = "uploads/" + user + "_" + time.Now().Format("20060102150405") + "_" + handler.Filename
			dst, err := os.Create("static/" + imagePath)
			if err != nil {
				http.Error(w, "Error saving image", http.StatusInternalServerError)
				return
			}
			defer dst.Close()

			if _, err := io.Copy(dst, file); err != nil {
				http.Error(w, "Error saving image", http.StatusInternalServerError)
				return
			}
		}

		_, err = db.Exec("INSERT INTO posts (author, content, image_path) VALUES (?, ?, ?)", user, content, imagePath)
		if err != nil {
			http.Error(w, "Error creating post", http.StatusInternalServerError)
			return
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
