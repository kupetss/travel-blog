package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Post struct {
	ID        int
	Author    string
	Content   string
	ImagePath string
	CreatedAt time.Time
}

type Comment struct {
	ID        int
	PostID    int
	Author    string
	Content   string
	CreatedAt time.Time
}

type User struct {
	Username string
}

var (
	db        *sql.DB
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"formatDate":     formatDate,
		"formatDateTime": formatDateTime,
		"relativeTime":   relativeTime,
	}).ParseGlob("templates/*.html"))
)

func main() {
	log.Println("[APP] Starting application...")

	initDatabase()
	defer db.Close()

	startServer()
}

func initDatabase() {
	var err error
	db, err = sql.Open("sqlite", "file:blog.db?_pragma=foreign_keys(1)&_time_format=sqlite")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Database connection failed:", err)
	}

	if os.Getenv("APP_ENV") == "development" {
		_, _ = db.Exec("DROP TABLE IF EXISTS comments")
		_, _ = db.Exec("DROP TABLE IF EXISTS posts")
		_, _ = db.Exec("DROP TABLE IF EXISTS users")
	}

	createTables()
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getCurrentUser(r)
	if user == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	postID := r.FormValue("post_id")
	if postID == "" {
		http.Error(w, "Post ID is required", http.StatusBadRequest)
		return
	}

	var author string
	err := db.QueryRow("SELECT author FROM posts WHERE id = ?", postID).Scan(&author)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	if author != user {
		http.Error(w, "You can only delete your own posts", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM posts WHERE id = ?", postID)
	if err != nil {
		http.Error(w, "Error deleting post", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusFound)
}

func createTables() {
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		author TEXT NOT NULL,
		content TEXT NOT NULL,
		image_path TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER NOT NULL,
		author TEXT NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
	);
	`
	if _, err := db.Exec(sqlStmt); err != nil {
		log.Fatal("Failed to create tables:", err)
	}
	log.Println("[DB] Tables created/verified")
}

func startServer() {
	if err := os.MkdirAll("static/uploads", 0755); err != nil {
		log.Fatal("Failed to create uploads directory:", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/profile", profileHandler)
	mux.HandleFunc("/create-post", createPostHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/delete-post", deletePostHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("[SERVER] Starting server on http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)

	if r.Method == "POST" && user != "" {
		postID := r.FormValue("post_id")
		comment := strings.TrimSpace(r.FormValue("comment"))

		if postID != "" && comment != "" {
			if _, err := db.Exec(
				"INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)",
				postID, user, comment,
			); err != nil {
				http.Error(w, "Error adding comment", http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	posts, err := getPosts()
	if err != nil {
		http.Error(w, "Error loading posts", http.StatusInternalServerError)
		return
	}

	comments, err := getCommentsForPosts(posts)
	if err != nil {
		http.Error(w, "Error loading comments", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "index.html", map[string]interface{}{
		"User":     user,
		"Posts":    posts,
		"Comments": comments,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if len(username) < 3 || len(password) < 6 {
			http.Error(w, "Username (min 3 chars) and password (min 6 chars) required", http.StatusBadRequest)
			return
		}

		if _, err := db.Exec(
			"INSERT INTO users (username, password) VALUES (?, ?)",
			username, password,
		); err != nil {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		setSessionCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "register.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		var dbPassword string
		err := db.QueryRow(
			"SELECT password FROM users WHERE username = ?",
			username,
		).Scan(&dbPassword)

		switch {
		case err == sql.ErrNoRows:
			if _, err := db.Exec(
				"INSERT INTO users (username, password) VALUES (?, ?)",
				username, password,
			); err != nil {
				http.Error(w, "Error creating user", http.StatusInternalServerError)
				return
			}
		case err != nil:
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		case dbPassword != password:
			http.Error(w, "Invalid credentials", http.StatusBadRequest)
			return
		}

		setSessionCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "login.html", nil)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		newUsername := strings.TrimSpace(r.FormValue("new_username"))
		newPassword := r.FormValue("new_password")

		if newUsername != "" || newPassword != "" {
			if _, err := db.Exec(
				"UPDATE users SET username = ?, password = ? WHERE username = ?",
				newUsername, newPassword, user,
			); err != nil {
				http.Error(w, "Error updating profile", http.StatusInternalServerError)
				return
			}
			setSessionCookie(w, newUsername)
			user = newUsername
		}
	}

	posts, err := getUserPosts(user)
	if err != nil {
		http.Error(w, "Error loading posts", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "profile.html", map[string]interface{}{
		"Username": user,
		"Posts":    posts,
	})
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method != "POST" {
		renderTemplate(w, "create_post.html", nil)
		return
	}

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		http.Error(w, "File too large or form error", http.StatusBadRequest)
		return
	}

	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	imagePath, err := saveUploadedFile(r, user)
	if err != nil && err != http.ErrMissingFile {
		http.Error(w, "Error processing image", http.StatusBadRequest)
		return
	}

	if _, err := db.Exec(
		"INSERT INTO posts (author, content, image_path) VALUES (?, ?, ?)",
		user, content, imagePath,
	); err != nil {
		http.Error(w, "Error creating post", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusFound)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.FormValue("query"))
	if query == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	posts, err := searchPosts(query)
	if err != nil {
		http.Error(w, "Error searching posts", http.StatusInternalServerError)
		return
	}

	comments, err := getCommentsForPosts(posts)
	if err != nil {
		http.Error(w, "Error loading comments", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "index.html", map[string]interface{}{
		"User":        getCurrentUser(r),
		"Posts":       posts,
		"Comments":    comments,
		"SearchQuery": query,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
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
		var p Post
		var createdAt string
		if err := rows.Scan(&p.ID, &p.Author, &p.Content, &p.ImagePath, &createdAt); err != nil {
			return nil, err
		}

		if t, err := parseDatabaseTime(createdAt); err == nil {
			p.CreatedAt = t
		}
		posts = append(posts, p)
	}
	return posts, rows.Err()
}

func getUserPosts(username string) ([]Post, error) {
	rows, err := db.Query(`
		SELECT id, content, image_path, created_at 
		FROM posts 
		WHERE author = ?
		ORDER BY created_at DESC
	`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		var createdAt string
		if err := rows.Scan(&p.ID, &p.Content, &p.ImagePath, &createdAt); err != nil {
			return nil, err
		}

		if t, err := parseDatabaseTime(createdAt); err == nil {
			p.CreatedAt = t
		}
		posts = append(posts, p)
	}
	return posts, rows.Err()
}

func getCommentsForPosts(posts []Post) (map[int][]Comment, error) {
	if len(posts) == 0 {
		return nil, nil
	}

	var postIDs []interface{}
	for _, p := range posts {
		postIDs = append(postIDs, p.ID)
	}

	query := `
		SELECT id, post_id, author, content, created_at 
		FROM comments 
		WHERE post_id IN (?` + strings.Repeat(",?", len(postIDs)-1) + `)
		ORDER BY created_at ASC
	`

	rows, err := db.Query(query, postIDs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	comments := make(map[int][]Comment)
	for rows.Next() {
		var c Comment
		var createdAt string
		if err := rows.Scan(&c.ID, &c.PostID, &c.Author, &c.Content, &createdAt); err != nil {
			return nil, err
		}

		if t, err := parseDatabaseTime(createdAt); err == nil {
			c.CreatedAt = t
		}
		comments[c.PostID] = append(comments[c.PostID], c)
	}
	return comments, rows.Err()
}

func searchPosts(query string) ([]Post, error) {
	rows, err := db.Query(`
		SELECT id, author, content, image_path, created_at 
		FROM posts 
		WHERE content LIKE ? OR author LIKE ? 
		ORDER BY created_at DESC
	`, "%"+query+"%", "%"+query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		var createdAt string
		if err := rows.Scan(&p.ID, &p.Author, &p.Content, &p.ImagePath, &createdAt); err != nil {
			return nil, err
		}

		if t, err := parseDatabaseTime(createdAt); err == nil {
			p.CreatedAt = t
		}
		posts = append(posts, p)
	}
	return posts, rows.Err()
}

func saveUploadedFile(r *http.Request, username string) (string, error) {
	file, header, err := r.FormFile("image")
	if err != nil {
		return "", err
	}
	defer file.Close()

	buff := make([]byte, 512)
	if _, err = file.Read(buff); err != nil {
		return "", err
	}

	if !strings.HasPrefix(http.DetectContentType(buff), "image/") {
		return "", fmt.Errorf("only image files are allowed")
	}

	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	ext := path.Ext(header.Filename)
	filename := fmt.Sprintf("%s_%d%s", username, time.Now().UnixNano(), ext)
	filePath := path.Join("uploads", filename)

	dst, err := os.Create(path.Join("static", filePath))
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err = io.Copy(dst, file); err != nil {
		return "", err
	}

	return filePath, nil
}

func getCurrentUser(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setSessionCookie(w http.ResponseWriter, username string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("Error rendering template %s: %v", name, err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func parseDatabaseTime(timeStr string) (time.Time, error) {
	layouts := []string{
		"2006-01-02 15:04:05",
		time.RFC3339,
		"2006-01-02T15:04:05Z",
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, timeStr)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %s", timeStr)
}

func formatDate(t time.Time) string {
	months := []string{
		"января", "февраля", "марта", "апреля", "мая", "июня",
		"июля", "августа", "сентября", "октября", "ноября", "декабря",
	}
	return fmt.Sprintf("%d %s %d", t.Day(), months[t.Month()-1], t.Year())
}

func formatDateTime(t time.Time) string {
	return fmt.Sprintf("%s в %02d:%02d", formatDate(t), t.Hour(), t.Minute())
}

func relativeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "только что"
	case diff < time.Hour:
		minutes := int(diff.Minutes())
		return fmt.Sprintf("%d %s назад", minutes, pluralize(minutes, "минуту", "минуты", "минут"))
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		return fmt.Sprintf("%d %s назад", hours, pluralize(hours, "час", "часа", "часов"))
	case diff < 48*time.Hour:
		return "вчера"
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%d %s назад", days, pluralize(days, "день", "дня", "дней"))
	default:
		return formatDate(t)
	}
}

func pluralize(n int, singular, few, many string) string {
	n = n % 100
	if n > 10 && n < 20 {
		return many
	}
	n = n % 10
	switch {
	case n == 1:
		return singular
	case n >= 2 && n <= 4:
		return few
	default:
		return many
	}
}
