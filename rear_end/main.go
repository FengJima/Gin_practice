package main

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"log"
	"main/Control_sql"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("Key") // 密钥，用于签署和验证令牌
// Demo function, not used in main
// Generates Passcode using a UTF-8 (not base32) secret and custom parameters
func GeneratePassCode(utf8string string) string {
	secret := base32.StdEncoding.EncodeToString([]byte(utf8string))
	passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
	if err != nil {
		panic(err)
	}
	return passcode
}
func generateToken(username string) (string, error) {
	claims := UserClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // 令牌的有效期，这里设置为 1 小时
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func parseToken(tokenString string) (*UserClaims, error) {
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1) // 剥离 "Bearer " 前缀
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("Invalid token")
}
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type UserClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
type UserStatusUpdate struct {
	UserID int  `json:"userID"`
	Status bool `json:"status"`
}

func main() {
	db, err := sql.Open("mysql", "root:123456@tcp(localhost:3306)/practice")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := gin.Default()
	// 设置静态资源文件夹路径
	r.Static("/static", "./static")
	r.GET("/", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/protected.html")
	})
	r.GET("/totpLogin", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/totpLogin.html")
	})
	r.GET("/totp", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/totp.html")
	})
	r.GET("/protected", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/protected.html")
	})
	r.GET("/login", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/login.html")
	})
	r.GET("register", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/register.html")
	})
	r.GET("/manage", func(c *gin.Context) {
		c.File("D:/code/goproject/rear_end/static/manage.html")
	})
	// //注册
	r.POST("/api/register", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 对密码进行哈希处理
		hashedPassword, err := hashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// 将用户信息存储到数据库
		_, err = db.Exec("INSERT INTO user (username, userpassword) VALUES (?, ?)", user.Username, hashedPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	})
	//审核
	//发送用户数据
	r.GET("/api/manage", func(c *gin.Context) {
		users := Control_sql.GetUsers(db)
		if users == nil {
			c.JSON(404, "error")
		}
		c.JSON(http.StatusOK, users)
	})
	//接受启用或禁用信息
	r.POST("/api/manage", func(c *gin.Context) {
		var userStatusUpdate UserStatusUpdate
		if err := c.ShouldBindJSON(&userStatusUpdate); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 获取解析后的数据
		userID := userStatusUpdate.UserID
		status := userStatusUpdate.Status

		// 在这里进行用户状态的更新逻辑，根据需要连接数据库或执行其他操作
		// 示例：根据userID更新用户状态为status
		var newStatus int
		if status {
			newStatus = 1 // 启用
		} else {
			newStatus = -1 // 禁用
		}
		_, err := db.Exec("UPDATE user SET status = ? WHERE id = ?", newStatus, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 返回响应
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("User %d status updated to %t", userID, status),
		})
	})
	//用户登录
	r.POST("/api/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// 根据用户名和密码验证用户
		// 这里应该添加密码加密比对
		var hashedPassword string
		var status int
		err := db.QueryRow("SELECT status,userpassword FROM user WHERE username = ?", user.Username).Scan(&status, &hashedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未注册"})
			return
		}
		// 验证密码
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
			return
		}
		//验证状态
		if status == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "正在审核中"})
			return
		} else if status == -1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "您已被禁用"})
			return
		}
		// 生成令牌
		token, err := generateToken(user.Username)
		if err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	})
	r.POST("/api/adminLogin", func(c *gin.Context) {
		var admin User
		if err := c.ShouldBindJSON(&admin); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		var hashedPassword string
		err := db.QueryRow("SELECT adminpassword FROM admin WHERE adminname = ?", admin.Username).Scan(&hashedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "管理员错误"})
			return
		}
		// 验证密码
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(admin.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "登录成功"})
	})
	r.POST("/api/totplogin", func(c *gin.Context) {

	})
	r.POST("/api/verifyToken", func(c *gin.Context) {
		// 从请求头中获取令牌
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is missing"})
			return
		}

		// 去除 "Bearer " 前缀
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		// 验证令牌有效性，使用JWT库解析和验证令牌
		claims, err := parseToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid"})
			return
		}

		// 令牌验证成功
		c.JSON(http.StatusOK, gin.H{"message": "Token is valid", "data": claims})
	})
	r.GET("/api/totp", func(c *gin.Context) {

		secretKey := "secret"

		// 生成验证码
		pass := GeneratePassCode(secretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate TOTP",
			})
			return
		}

		// 返回生成的TOTP验证码
		c.JSON(http.StatusOK, gin.H{
			"totp": pass,
		})
	})
	r.Run(":8080")
}
