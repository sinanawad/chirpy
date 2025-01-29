package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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
		apiCfg.fileserverHits.Store(0)
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

func validateChirp() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type inputParams struct {
			Body string `json:"body"`
		}

		type validParams struct {
			CleanedBody string `json:"cleaned_body"`
		}

		type errParams struct {
			ErrorRet string `json:"error"`
		}

		retDetail := "Chirp is valid"
		retStatus := 200

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

		if retStatus == 200 {
			cleanedMsg := removeProfanity(params.Body)
			fmt.Println("cleanedMsg: ", cleanedMsg)
			retOK := validParams{
				CleanedBody: cleanedMsg,
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

func main() {

	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	serveMux.Handle("/healthz", err405Handler())
	serveMux.Handle("/metrics", err405Handler())

	serveMux.Handle("GET /healthz", healthHandler())
	serveMux.Handle("GET /metrics", printMetricsHandler())

	serveMux.Handle("/reset", err405Handler())
	serveMux.Handle("POST /reset", resetMetricsHandler())

	serveMux.Handle("/api/validate_chirp", err405Handler())
	serveMux.Handle("POST /api/validate_chirp", validateChirp())

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	server.ListenAndServe()

}
