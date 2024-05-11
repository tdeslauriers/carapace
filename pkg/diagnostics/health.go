package diagnostics

import (
	"encoding/json"
	"log"
	"net/http"
)

type HealthCheck struct {
	Status string `json:"status"`
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {

	h := HealthCheck{"UP"}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h); err != nil {
		log.Printf("unable to send status: UP response body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": 500,"message":"Internal Server Error"}`))
		return
	}
}
