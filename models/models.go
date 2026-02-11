package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type AddExpenseRequest struct {
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Amount      float64 `json:"amount"`
}

type UpdateExpenseRequest struct {
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Amount      float64 `json:"amount"`
}

type GetExpensesResponse struct {
	ID          int       `json:"id"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Amount      float64   `json:"amount"`
	CreatedAt   time.Time `json:"created_at"`
}
