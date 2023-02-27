package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/semmidev/go-magang/auth"
	"github.com/semmidev/go-magang/token"
	"golang.org/x/oauth2"
)

//go:embed views/*
var Resources embed.FS

//go:embed public
var StaticFiles embed.FS

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	symmetricKey := GetEnv("SYMMETRIC_KEY", "76440225709465899502497877279549")
	tokenMaker, err := token.NewPasetoMaker(symmetricKey)
	if err != nil {
		log.Fatalf("failed to create token maker: %v", err)
	}

	r.Get("/public/*", http.StripPrefix("/public", fsHandler()).ServeHTTP)

	dbConn, dbErr := ConnectDB()
	if dbErr != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	handlers := &handlers{
		internRepo: NewRepository(dbConn),
		tokenMaker: tokenMaker,
		embed:      Resources,
	}

	r.Get("/login", handlers.handleLoginPage)
	r.Post("/admin/login", handlers.handleAdminLoginProcess)
	r.Get("/auth/google/login", handlers.handleGoogleLogin)
	r.Get("/auth/google/callback", handlers.handleGoogleCallback)

	r.With(auth.MustLoginMiddleware(tokenMaker)).Get("/", handlers.handleHomePage)
	r.With(auth.MustLoginMiddleware(tokenMaker)).Get("/complete-personal-data", handlers.handleCompletePersonalData)
	r.With(auth.MustLoginMiddleware(tokenMaker)).Post("/complete-personal-data", handlers.handleCompletePersonalDataProcess)

	r.Get("/success", handlers.handleSuccessPage)
	r.Get("/error", handlers.handleErrorPage)
	r.Get("/logout", handlers.handleLogout)

	serverPort := GetEnv("PORT", "8080")
	fmt.Println("Server started on port", serverPort)
	log.Fatal(http.ListenAndServe(":" + serverPort, r))
}

var views = map[string]*template.Template{
	"login":                  template.Must(template.ParseFS(Resources, path.Join("views", "login.html"))),
	"complete-personal-data": template.Must(template.ParseFS(Resources, path.Join("views", "complete-personal-data.html"))),
	"intern-dashboard":       template.Must(template.ParseFS(Resources, path.Join("views", "intern-dashboard.html"))),
	"admin-dashboard":        template.Must(template.ParseFS(Resources, path.Join("views", "admin-dashboard.html"))),
	"error":                  template.Must(template.ParseFS(Resources, path.Join("views", "error.html"))),
	"success":                template.Must(template.ParseFS(Resources, path.Join("views", "success.html"))),
}

type handlers struct {
	internRepo *Repository
	tokenMaker token.Maker
	embed      embed.FS
}

func fsHandler() http.Handler {
	sub, err := fs.Sub(StaticFiles, "public")
	if err != nil {
		log.Fatalf("failed to open static files: %v", err)
	}
	return http.FileServer(http.FS(sub))
}

func (h *handlers) handleAdminLoginProcess(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusBadRequest, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email != "admin@gmail.com" && password != "admin" {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusUnauthorized, "invalid email or password")
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	duration := time.Hour * 24 * 30
	pasetoToken, _, err := h.tokenMaker.CreateToken("admin@gmail.com", "admin", duration)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	cookie := http.Cookie{
		Path:    "/",
		Name:    "access_token",
		Value:   pasetoToken,
		Expires: time.Now().Add(duration),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handlers) handleCompletePersonalDataProcess(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(auth.AuthorizationPayloadKey).(*token.Payload)
	if payload.Role != "intern" {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusUnauthorized, "you are not authorized to access this page")
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	err := r.ParseForm()
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusBadRequest, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	intern, err := h.internRepo.FindInternByEmail(payload.Email)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	fullName := r.FormValue("full-name")
	school := r.FormValue("school")
	phoneNumber := r.FormValue("phone-number")
	division := r.FormValue("division")
	gender := r.FormValue("gender")
	startDate := r.FormValue("start-date")
	endDate := r.FormValue("end-date")

	internForUpdate := Intern{
		ID:          intern.ID,
		Name:        intern.Name,
		Email:       intern.Email,
		Picture:     intern.Picture,
		FullName:    &fullName,
		School:      &school,
		PhoneNumber: &phoneNumber,
		Division:    &division,
		Gender:      &gender,
		StartDate:   &startDate,
		EndDate:     &endDate,
	}

	err = h.internRepo.UpdateIntern(internForUpdate)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/success", http.StatusSeeOther)
}

func (h *handlers) handleCompletePersonalData(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(auth.AuthorizationPayloadKey).(*token.Payload)
	if payload.Role != "intern" {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusUnauthorized, "you are not authorized to access this page")
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	intern, err := h.internRepo.FindInternByEmail(payload.Email)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	if intern.FullName != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err = views["complete-personal-data"].Execute(w, intern)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
}

func (h *handlers) handleHomePage(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(auth.AuthorizationPayloadKey).(*token.Payload)

	if payload.Role == "admin" {
		interns, err := h.internRepo.FindAllInterns()
		if err != nil {
			url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
			http.Redirect(w, r, url, http.StatusSeeOther)
			return
		}

		if len(interns) == 0 {
			interns = []Intern{}
		}

		internsData := struct {
			Interns []Intern `json:"interns"`
		}{
			Interns: interns,
		}

		err = views["admin-dashboard"].Execute(w, internsData)
		if err != nil {
			url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
			http.Redirect(w, r, url, http.StatusSeeOther)
			return
		}
		return
	}

	intern, err := h.internRepo.FindInternByEmail(payload.Email)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	if intern.FullName == nil {
		http.Redirect(w, r, "/complete-personal-data", http.StatusSeeOther)
		return
	}

	err = views["intern-dashboard"].Execute(w, intern)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
}

func (h *handlers) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	err := views["login"].Execute(w, nil)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
}

func (h *handlers) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := auth.GoogleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *handlers) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	exchange, err := auth.GoogleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusBadRequest, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + exchange.AccessToken)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusBadRequest, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusBadRequest, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	userInfoStruct := Intern{
		ID:      userInfo["id"].(string),
		Name:    userInfo["name"].(string),
		Email:   userInfo["email"].(string),
		Picture: userInfo["picture"].(string),
	}

	err = h.internRepo.SaveIntern(userInfoStruct)
	if err != nil {
		if !errors.Is(err, ErrInternAlreadyExists) {
			url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
			http.Redirect(w, r, url, http.StatusSeeOther)
			return
		}
	}

	// get intern from db
	intern, err := h.internRepo.FindInternByID(userInfoStruct.ID)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	duration := time.Hour * 24 * 30
	pasetoToken, _, err := h.tokenMaker.CreateToken(userInfoStruct.Email, "intern", duration)
	if err != nil {
		url := fmt.Sprintf("/error?code=%d&message=%s", http.StatusInternalServerError, err.Error())
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	cookie := http.Cookie{
		Path:    "/",
		Name:    "access_token",
		Value:   pasetoToken,
		Expires: time.Now().Add(duration),
	}

	http.SetCookie(w, &cookie)

	// check if intern has completed personal data
	// just check if intern has full name
	if intern.FullName != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/complete-personal-data", http.StatusSeeOther)
}

func (h *handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Path:    "/",
		Name:    "access_token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *handlers) handleErrorPage(w http.ResponseWriter, _ *http.Request) {
	err := views["error"].Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) handleSuccessPage(w http.ResponseWriter, _ *http.Request) {
	err := views["success"].Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func GetEnv(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
