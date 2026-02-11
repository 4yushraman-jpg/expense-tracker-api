package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

func InitDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	var err error
	DB, err = sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal(err)
	}

	query := `CREATE TABLE IF NOT EXISTS users(
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);`

	_, err = DB.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	query = `CREATE TABLE IF NOT EXISTS expenses(
		id SERIAL PRIMARY KEY,
		description TEXT NOT NULL,
		category TEXT NOT NULL,
		amount DECIMAL NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`

	_, err = DB.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to PostgreSQL, tables created successfully")
}
