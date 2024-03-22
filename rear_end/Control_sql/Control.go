package Control_sql

import (
	"database/sql"
	"log"
)

type User struct {
	UserID       int    `json:"userID"`
	Username     string `json:"username"`
	UserPassword string `json:"userpassword"`
	Status       int    `json:"status"`
}

func SearchUserByName(db *sql.DB, username string) User {
	var user User
	err := db.QueryRow("SELECT id, username,userpassword, email FROM user WHERE username = ?", username).Scan(&user.UserID, &user.Username, &user.UserPassword)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}
	return user
}
func AddUser(db *sql.DB, user User) {
	_, err := db.Exec("INSERT INTO user (username, email, userpassword) VALUES (?, ?, ?)", user.Username, user.UserPassword)
	if err != nil {
		log.Fatal(err)
	}
}
func ChangeUserStatus(db *sql.DB, id int, ispass bool) {
	var status int
	if ispass {
		status = 1
	} else {
		status = 2
	}
	_, err := db.Exec("UPDATE user SET status = ? WHERE id = ?", status, id)
	if err != nil {
		log.Fatal(err)
	}
}
func GetUsers(db *sql.DB) []User {
	rows, err := db.Query("SELECT * FROM User ")
	if err != nil {
		return nil
	}
	var users []User

	for rows.Next() {
		var user User

		err := rows.Scan(&user.UserID, &user.Username, &user.UserPassword, &user.Status)

		if err != nil {
			// handle error
		}

		users = append(users, user)
	}
	return users
}
