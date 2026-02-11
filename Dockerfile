# ---------- Build Stage ----------
FROM golang:alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy full project
COPY . .

# Build the application (main.go is in root)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

# ---------- Runtime Stage ----------
FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app .

EXPOSE 8080

CMD ["./app"]
