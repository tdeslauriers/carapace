package diagnostics

import (
	"encoding/json"
	"net/http"
)

type HealthCheck struct {
	Status string `json:"status"`
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {

	h := HealthCheck{"Ok"}

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(h)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
