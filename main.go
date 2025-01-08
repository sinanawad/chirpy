package main

import (
	"fmt"
	"net/http"
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

func main() {

	serveMux := http.NewServeMux()
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	serveMux.Handle("/healthz", err405Handler())
	serveMux.Handle("/metrics", err405Handler())

	serveMux.Handle("GET /healthz", healthHandler())
	serveMux.Handle("GET /metrics", printMetricsHandler())

	serveMux.Handle("/reset", err405Handler())
	serveMux.Handle("POST /reset", resetMetricsHandler())

	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	server.ListenAndServe()

}
