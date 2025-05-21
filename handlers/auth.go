package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func ShowLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"Timestamp": time.Now().UnixNano(),
	})
}

func ShowRegisterForm(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{
		"Timestamp": time.Now().UnixNano(),
	})
}

func Register(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == "" || password == "" {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "Username and password are required",
			})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Failed to hash password",
			})
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)",
			username, string(hashedPassword))
		if err != nil {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"error": "Username already exists",
			})
			return
		}

		c.Redirect(http.StatusFound, "/login")
	}
}

func Login(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var id int
		var hashedPassword string
		err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&id, &hashedPassword)
		if err != nil {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"error": "Invalid username or password",
			})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"error": "Invalid username or password",
			})
			return
		}

		c.SetCookie("user_id", strconv.Itoa(id), 3600, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
	}
}

func Logout(c *gin.Context) {
	c.SetCookie("user_id", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}
