package api

import (
	"encoding/json"
	"net/http"
)

const maxJSONBodyBytes = 8 << 20 // 8 MiB

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	}
	return json.NewDecoder(r.Body).Decode(dst)
}
