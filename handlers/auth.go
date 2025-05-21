package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Register(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Username already exists"})
			return
		}

		// Получаем ID нового пользователя
		userID, _ := result.LastInsertId()

		// Устанавливаем куки
		c.SetCookie("user_id", strconv.FormatInt(userID, 10), 3600, "/", "", false, true)
		c.Redirect(http.StatusFound, "/")
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
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid credentials"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid credentials"})
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

func ShowRegisterForm(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{})
}

func ShowLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}
