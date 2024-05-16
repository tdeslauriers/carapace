package diagnostics

import (
	"encoding/json"
	"net/http"
)

type HealthCheck struct {
	Status string `json:"status"`
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {

	hc := HealthCheck{"UP"}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(hc); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": 500,"message":"Internal Server Error"}`))
		return
	}
}
