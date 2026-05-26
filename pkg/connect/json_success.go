package connect

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
)

func SendJsonSuccess[T any](w http.ResponseWriter, statusCode int, payload T) {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		
		slog.Error("failed to encode json response", "err", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code":500,"message":"failed to encode json response"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(buf.Bytes())
}
