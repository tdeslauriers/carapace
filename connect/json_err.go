package connect

import (
	"encoding/json"
	"log"
	"net/http"
)

type ErrorHttp struct {
	StatusCode int    `json:"code"`
	Message    string `json:"message"`
}

func (e ErrorHttp) SendJsonErr(w http.ResponseWriter) {

	w.Header().Set("Content-Type", "application/json")

	jsonErr, err := json.Marshal(e)
	if err != nil {
		log.Printf("error marshalling http error response to json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": 500, "message": "Internal Server Error"}`))
		return
	}

	w.WriteHeader(e.StatusCode)
	w.Write(jsonErr)
}
