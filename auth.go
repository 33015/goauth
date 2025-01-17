package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxSessionAge = 24 * time.Hour

func SignUp(username string, password string, db *sql.DB) error {
	createUserQuery := "INSERT INTO users (username, password) VALUES ($1, $2)"
	_, err := db.Exec(createUserQuery, username, password)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func getPassword(username string, db *sql.DB) (string, error) {
	query := "SELECT password FROM users WHERE username = $1"
	var name string
	err := db.QueryRow(query, username).Scan(&name)
	if err != nil {
		return "", err
	}

	return name, nil
}

func CheckPassword(username string, password string, db *sql.DB) error {
	pw, err := getPassword(username, db)
	if err != nil {
		log.Println(err)
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(password))
	if err != nil {
		log.Println("Error Invalid username or password", err)
		return err
	}
	return nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// session stores the user's session information
type session struct {
	UserID    int
	Username  string
	CreatedAt time.Time
}

// SessionManager handles session storage and management
type SessionManager struct {
	sessions map[string]session
	mu       sync.RWMutex
}

var sessionManager = &SessionManager{
	sessions: make(map[string]session),
}

// Periodic session cleanup (call this in a goroutine when starting your server)
func CleanupSessions() {
	for {
		time.Sleep(1 * time.Hour)

		sessionManager.mu.Lock()
		for id, session := range sessionManager.sessions {
			if time.Since(session.CreatedAt) > maxSessionAge {
				delete(sessionManager.sessions, id)
			}
		}
		sessionManager.mu.Unlock()
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := getSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// check sessuion age
		if time.Since(session.CreatedAt) > maxSessionAge {
			RemoveSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func getSession(r *http.Request) (*session, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	sessionManager.mu.RLock()
	defer sessionManager.mu.RUnlock()
	session, exists := sessionManager.sessions[cookie.Value]
	if !exists {
		log.Println("session not found", exists)
		return nil, errors.New("session not found")
	}
	return &session, nil
}

func RemoveSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		sessionManager.mu.Lock()
		delete(sessionManager.sessions, cookie.Value)
		sessionManager.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func SetSession(username string, w http.ResponseWriter) error {
	sessionID, err := generateSessionID()
	if err != nil {
		log.Println(err)
		return err
	}

	sessionManager.mu.Lock()
	sessionManager.sessions[sessionID] = session{
		Username:  username,
		CreatedAt: time.Now(),
	}
	sessionManager.mu.Unlock()
	// Set session cookie
	cookie := &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true, // Enable in production with HTTPS
		MaxAge:   86400, // 1 day
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
	return err
}
