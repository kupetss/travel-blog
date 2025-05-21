package main

import (
	"database/sql"
	"log"
	"net/http"
	"travel-blog/handlers"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/register" || c.Request.URL.Path == "/login" {
			c.Next()
			return
		}

		_, err := c.Cookie("user_id")
		if err != nil && c.Request.URL.Path != "/" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	db, err := sql.Open("sqlite", "blog.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создаем таблицы если их нет
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.Use(authMiddleware()) // Добавляем middleware
	r.LoadHTMLGlob("templates/*.html")

	// Маршруты авторизации
	r.GET("/register", handlers.ShowRegisterForm)
	r.POST("/register", handlers.Register(db))
	r.GET("/login", handlers.ShowLoginForm)
	r.POST("/login", handlers.Login(db))
	r.GET("/logout", handlers.Logout)

	// Маршруты постов
	r.GET("/", handlers.ShowPosts(db))
	r.GET("/post", handlers.ShowPostForm)
	r.POST("/post", handlers.CreatePost(db))

	log.Println("Server started on :8080")
	log.Fatal(r.Run(":8080"))
}
