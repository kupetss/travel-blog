package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func ShowPostForm(c *gin.Context) {
	userID, err := c.Cookie("user_id")
	if err != nil || userID == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.HTML(http.StatusOK, "post.html", nil)
}

func CreatePost(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := c.Cookie("user_id")
		if err != nil || userID == "" {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		title := c.PostForm("title")
		content := c.PostForm("content")

		_, err = db.Exec("INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
			userID, title, content, time.Now())
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		c.Redirect(http.StatusFound, "/")
	}
}

func ShowPosts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Cookie("user_id")

		rows, err := db.Query(`
            SELECT posts.id, posts.title, posts.content, posts.created_at, users.username 
            FROM posts 
            JOIN users ON posts.user_id = users.id 
            ORDER BY posts.created_at DESC
        `)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []struct {
			ID        int
			Title     string
			Content   string
			CreatedAt time.Time
			Author    string
		}

		for rows.Next() {
			var post struct {
				ID        int
				Title     string
				Content   string
				CreatedAt time.Time
				Author    string
			}
			err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.CreatedAt, &post.Author)
			if err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
				return
			}
			posts = append(posts, post)
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"Posts":  posts,
			"UserID": userID, // передаем ID пользователя в шаблон
		})
	}
}
