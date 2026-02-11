package main

import (
	"log"
	"net/http"

	"expense-tracker-api/database"
	"expense-tracker-api/handlers"
	"expense-tracker-api/middleware"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found")
	}

	database.InitDB()
	middleware.InitJWT()

	http.HandleFunc("POST /api/signup", handlers.SignupHandler)
	http.HandleFunc("POST /api/login", handlers.LoginHandler)

	http.HandleFunc("GET /api/expenses", middleware.AuthMiddleware(handlers.GetExpensesHandler))
	http.HandleFunc("POST /api/expenses", middleware.AuthMiddleware(handlers.AddExpenseHandler))
	http.HandleFunc("PUT /api/expenses/{id}", middleware.AuthMiddleware(handlers.UpdateExpenseHandler))
	http.HandleFunc("DELETE /api/expenses/{id}", middleware.AuthMiddleware(handlers.DeleteExpenseHandler))

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
