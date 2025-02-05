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
	"github.com/sinanawad/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
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

		decoder := json.NewDecoder(r.Body)
		params := inputParams{}

		err := decoder.Decode(&params)

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
				Body:   removeProfanity(params.Body),
				UserID: uuid.NullUUID{UUID: uuid.MustParse(params.UserID), Valid: true},
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

func (cfg *apiConfig) createUserHdlr() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type inParams struct {
			Email string `json:"email"`
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

		user, err := cfg.dbQueries.CreateUser(r.Context(), params.Email)
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
		db := cfg.dbQueries
		chirps, err := db.GetChirps(r.Context())
		if err != nil {
			log.Printf("Error getting chirps: %s", err)
			w.WriteHeader(500)
			return
		}

		type chirp struct {
			ID        uuid.UUID `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    uuid.UUID `json:"user_id"`
		}

		var chirpsResp []chirp
		for _, c := range chirps {
			fmt.Printf("Chirp: %v\n", c)
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

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return
	}

	defer db.Close()

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "unknown"
	} else {
		platform = strings.ToLower(platform)
	}

	apiCfg.dbQueries = database.New(db)
	apiCfg.platform = platform

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

	serveMux.Handle("/api/chirps", err405Handler())
	serveMux.Handle("POST /api/chirps", apiCfg.createChirpHdlr())
	serveMux.Handle("GET /api/chirps", apiCfg.getChirpsHdlr())

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	server.ListenAndServe()

}
