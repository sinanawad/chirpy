package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sinanawad/chirpy/internal/auth"
	"github.com/sinanawad/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	secret         string
}

var apiCfg apiConfig = apiConfig{}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	// ...
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		fmt.Println("fileserverHits: ", cfg.fileserverHits.Load())
		// ...
		next.ServeHTTP(w, r)
		// ...
	})
}

func printMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") //Content-Type: text/plain; charset=utf-8 header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hits: " + fmt.Sprint(apiCfg.fileserverHits.Load())))
	})
}

func resetMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// reset the counter
		ret := http.StatusOK

		apiCfg.fileserverHits.Store(0)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") //Content-Type: text/plain; charset=utf-8 header

		if apiCfg.platform == "dev" {

			err := apiCfg.dbQueries.Reset(r.Context())
			if err != nil {
				log.Printf("Error resetting metrics: %s", err)
				w.WriteHeader(500)
				return
			}

			ret = http.StatusOK
		} else {
			ret = http.StatusForbidden
		}

		w.WriteHeader(ret)
	})
}

func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") //Content-Type: text/plain; charset=utf-8 header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func err405Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8") //Content-Type: text/plain; charset=utf-8 header
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("405"))
	})
}

/*
replace any of the following words in the Chirp with the static 4-character string ****:

kerfuffle
sharbert
fornax
Be sure to match against uppercase versions of the words as well, but not punctuation. "Sharbert!" does not need to be replaced, we'll consider it a different word due to the exclamation point. Finally, instead of the valid boolean, your handler should return the cleaned version of the text in a JSON response:
*/
func removeProfanity(msg string) string {
	cleanedMsg := msg
	profanityWords := []string{"kerfuffle", "sharbert", "fornax"}
	splitMsg := strings.Split(cleanedMsg, " ")
	var joinedMsg []string

	for _, word := range splitMsg {
		for _, profanityWord := range profanityWords {
			if strings.ToLower(word) == profanityWord {
				word = "****"
			}
		}
		joinedMsg = append(joinedMsg, word)
	}

	cleanedMsg = strings.Join(joinedMsg, " ")
	return cleanedMsg

}

func (cfg *apiConfig) createChirpHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("<<<< createChirpHdlr")
		defer fmt.Println(">>>> createChirpHdlr")

		type inputParams struct {
			Body   string `json:"body"`
			UserID string `json:"user_id"`
		}

		type errParams struct {
			ErrorRet string `json:"error"`
		}

		type savedChirp struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		retDetail := "Chirp is valid"
		retStatus := 201

		bearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			retDetail = "Unauthorized"
			retStatus = 401
		}

		tokenUuid, err := auth.ValidateJWT(bearerToken, apiCfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			retDetail = "Unauthorized"
			retStatus = 401
		}

		if tokenUuid == uuid.Nil {
			retDetail = "Unauthorized"
			retStatus = 401
		}

		decoder := json.NewDecoder(r.Body)
		params := inputParams{}

		err = decoder.Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			retDetail = "Something went wrong"
			retStatus = 400
		} else if len(params.Body) > 140 {
			retDetail = "Chirp is too long"
			retStatus = 400
		}

		retError := errParams{
			ErrorRet: retDetail,
		}

		var respBody interface{}

		if retStatus == 201 {
			// create chirp
			paramsChirp := database.CreateChirpParams{
				Body: removeProfanity(params.Body),
				//UserID: uuid.NullUUID{UUID: uuid.MustParse(params.UserID), Valid: true},
				UserID: uuid.NullUUID{UUID: tokenUuid, Valid: true},
			}

			chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), paramsChirp)
			if err != nil {
				log.Printf("Error creating chirp: %s", err)
				retStatus = 500
			}
			retOK := savedChirp{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID.UUID,
			}
			respBody = retOK
		} else {
			respBody = retError
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retStatus)
		w.Write(dat)

		// params is a struct with data populated successfully
		// ...
	})
}

func (cfg *apiConfig) updateUserHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> updateUserHdlr")
		defer fmt.Println("<<<< updateUserHdlr")

		type inParams struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := inParams{}

		err := decoder.Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(400)
			return
		}

		accessToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			fmt.Printf("Error GetBearerToken: %s", err)
			w.WriteHeader(401)
			return
		}

		dbUserUUID, err := auth.ValidateJWT(accessToken, cfg.secret)
		if err != nil || dbUserUUID == uuid.Nil {
			fmt.Printf("Error ValidateJWT: %s", err)
			w.WriteHeader(401)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)

		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			return
		}
		up := database.UpdateUserParams{
			ID:             dbUserUUID,
			Email:          params.Email,
			HashedPassword: hashedPassword,
		}

		usr, err := cfg.dbQueries.UpdateUser(r.Context(), up)
		if err != nil {
			log.Printf("Error updating user: %s", err)
			w.WriteHeader(500)
			return
		}

		type localUser struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
		}

		lu := localUser{
			ID:        dbUserUUID,
			CreatedAt: usr.CreatedAt,
			UpdatedAt: usr.UpdatedAt,
			Email:     usr.Email,
		}

		dat, err := json.Marshal(lu)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	})
}

func (cfg *apiConfig) createUserHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> createUserHdlr")
		defer fmt.Println("<<<< createUserHdlr")

		type inParams struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		type localUser struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
		}

		decoder := json.NewDecoder(r.Body)
		params := inParams{}

		err := decoder.Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(400)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)

		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			return
		}

		up := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		}

		user, err := cfg.dbQueries.CreateUser(r.Context(), up)
		if err != nil {
			log.Printf("Error creating user: %s", err)
			w.WriteHeader(500)
			return
		}

		lu := localUser{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}

		dat, err := json.Marshal(lu)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(dat)

	})
}

func (cfg *apiConfig) getChirpsHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> getChirpsHdlr")
		defer fmt.Println("<<<< getChirpsHdlr")

		db := cfg.dbQueries
		type chirp struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		path := r.PathValue("id")
		if path != "" {
			fmt.Printf("Path: %s\n", path)

			dbChirp, err := db.GetOneChirp(r.Context(), uuid.MustParse(path))
			if err != nil {
				log.Printf("Error getting chirp: %s", err)
				w.WriteHeader(404)
				return
			}

			var chirpResp chirp = chirp{
				ID:        dbChirp.ID,
				CreatedAt: dbChirp.CreatedAt,
				UpdatedAt: dbChirp.UpdatedAt,
				Body:      dbChirp.Body,
				UserID:    dbChirp.UserID.UUID,
			}

			dat, err := json.Marshal(chirpResp)
			if err != nil {
				log.Printf("Error marshalling JSON: %s", err)
				w.WriteHeader(500)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(dat)
			return
		}

		chirps, err := db.GetChirps(r.Context())
		if err != nil {
			log.Printf("Error getting chirps: %s", err)
			w.WriteHeader(500)
			return
		}

		var chirpsResp []chirp
		for _, c := range chirps {
			chirpsResp = append(chirpsResp, chirp{
				ID:        c.ID,
				CreatedAt: c.CreatedAt,
				UpdatedAt: c.UpdatedAt,
				Body:      c.Body,
				UserID:    c.UserID.UUID,
			})
		}

		dat, err := json.Marshal(chirpsResp)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	})
}

func (cfg *apiConfig) deleteChirpsHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> deleteChirpsHdlr")
		defer fmt.Println("<<<< deleteChirpsHdlr")

		bearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %s", err)
			w.WriteHeader(401)
			return
		}

		tokenUuid, err := auth.ValidateJWT(bearerToken, apiCfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %s", err)
			w.WriteHeader(401)
		}

		db := cfg.dbQueries
		// type chirp struct {
		// 	ID        uuid.UUID `json:"id"`
		// 	CreatedAt time.Time `json:"created_at"`
		// 	UpdatedAt time.Time `json:"updated_at"`
		// 	Body      string    `json:"body"`
		// 	UserID    uuid.UUID `json:"user_id"`
		// }

		path := r.PathValue("id")
		if path == "" {
			fmt.Printf("No chirp ID")
			w.WriteHeader(400)
			return
		}

		dbChirp, err := db.GetOneChirp(r.Context(), uuid.MustParse(path))
		if err != nil {
			log.Printf("Error getting chirp: %s", err)
			w.WriteHeader(404)
			return
		}

		if dbChirp.UserID.UUID != tokenUuid {
			log.Printf("Error deleting chirp, Unauthorized: %s", err)
			w.WriteHeader(403)
			return
		}

		dbChirp, err = db.DeleteChirp(r.Context(), dbChirp.ID)
		if err != nil {
			log.Printf("Error deleting chirp: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(204)
	})
}

func (cfg *apiConfig) chirpyLoginHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> chirpyLoginHdlr")
		defer fmt.Println("<<<< chirpyLoginHdlr")

		const defaultExpiryTime = 3600
		type inParams struct {
			Password   string `json:"password"`
			Email      string `json:"email"`
			ExpiryTime int    `json:"expires_in_seconds"`
		}

		type localUser struct {
			ID           uuid.UUID `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			UpdatedAt    time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
		}

		decoder := json.NewDecoder(r.Body)
		params := inParams{}

		err := decoder.Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(400)
			return
		}
		if params.ExpiryTime == 0 {
			params.ExpiryTime = defaultExpiryTime
		}
		user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			w.WriteHeader(500)
			return
		}

		err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil {
			w.WriteHeader(401)
			return
		}

		lu := localUser{}
		lu.ID = user.ID
		lu.CreatedAt = user.CreatedAt
		lu.UpdatedAt = user.UpdatedAt
		lu.Email = user.Email
		lu.Token, err = auth.MakeJWT(user.ID, apiCfg.secret)
		if err != nil {
			log.Printf("Error making JWT: %s", err)
			w.WriteHeader(500)
			return
		}
		lu.RefreshToken, err = auth.MakeRefreshToken()
		if err != nil {
			log.Printf("Error making refresh token: %s", err)
			w.WriteHeader(500)
			return
		}

		_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     lu.RefreshToken,
			UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
			ExpiresAt: time.Now().Add(time.Duration(60*24) * time.Hour),
		})
		if err != nil {
			log.Printf("Error saving refreshToken: %s", err)
			w.WriteHeader(500)
			return
		}

		dat, err := json.Marshal(lu)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)

	})
}

func (cfg *apiConfig) refreshTokenHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		fmt.Println(">>>> refreshTokenHdlr")
		defer fmt.Println("<<<< refreshTokenHdlr")

		type retParams struct {
			Token string `json:"token"`
		}

		retStatus := 200

		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			fmt.Printf("Error GetBearerToken: %s", err)
			retStatus = 401
		}
		fmt.Println(">>>> refreshTokenHdlr - token ", refreshToken)

		refreshTokenDb, err := apiCfg.dbQueries.GetRefreshToken(r.Context(), refreshToken)
		if err != nil {
			fmt.Printf("Error GetRefreshToken: %s", err)
			retStatus = 401
		}

		if refreshTokenDb.Token == "" || refreshTokenDb.UserID.UUID == uuid.Nil || refreshTokenDb.RevokedAt.Valid {
			fmt.Printf("Error invalid Token: %s", refreshTokenDb.Token)
			retStatus = 401
		}

		// create a new JWT
		token, err := auth.MakeJWT(refreshTokenDb.UserID.UUID, apiCfg.secret)
		if err != nil {
			fmt.Printf("Error MakeJWT: %s", err)
			retStatus = 500
		}

		params := retParams{
			Token: token,
		}

		var respBody interface{}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(retStatus)

		if retStatus == 200 {
			respBody = params

			dat, err := json.Marshal(respBody)
			if err != nil {
				fmt.Printf("Error marshalling JSON: %s", err)
				w.WriteHeader(500)
				return
			}
			w.Write(dat)
		}

	})
}

func (cfg *apiConfig) revokeRefreshTokenHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(">>>> RevokeRefreshTokenHdlr")
		defer fmt.Println("<<<< RevokeRefreshTokenHdlr")

		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Println(">>>> revokeRefreshToken - token ", refreshToken)

		_, err = apiCfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent) // 204 status code
	})
}

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return
	}

	mySecret := os.Getenv("MYSECRET")

	defer db.Close()

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "unknown"
	} else {
		platform = strings.ToLower(platform)
	}

	apiCfg.dbQueries = database.New(db)
	apiCfg.platform = platform
	apiCfg.secret = mySecret

	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	serveMux.Handle("/healthz", err405Handler())
	serveMux.Handle("/metrics", err405Handler())

	serveMux.Handle("GET /healthz", healthHandler())
	serveMux.Handle("GET /metrics", printMetricsHandler())

	serveMux.Handle("/admin/reset", err405Handler())
	serveMux.Handle("POST /admin/reset", resetMetricsHandler())

	serveMux.Handle("/api/users", err405Handler())
	serveMux.Handle("POST /api/users", apiCfg.createUserHdlr())
	serveMux.Handle("PUT /api/users", apiCfg.updateUserHdlr())

	serveMux.Handle("/api/chirps", err405Handler())
	serveMux.Handle("POST /api/chirps", apiCfg.createChirpHdlr())
	serveMux.Handle("GET /api/chirps/{id}", apiCfg.getChirpsHdlr())
	serveMux.Handle("DELETE /api/chirps/{id}", apiCfg.deleteChirpsHdlr())

	serveMux.Handle("/api/login", err405Handler())
	serveMux.Handle("POST /api/login", apiCfg.chirpyLoginHdlr())

	serveMux.Handle("/api/refresh", err405Handler())
	serveMux.Handle("POST /api/refresh", apiCfg.refreshTokenHdlr())

	serveMux.Handle("/api/revoke", err405Handler())
	serveMux.Handle("POST /api/revoke", apiCfg.revokeRefreshTokenHdlr())

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	server.ListenAndServe()

}
