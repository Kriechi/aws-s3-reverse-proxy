package proxy

import (
	"fmt"
	"net/http"
)

func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "OK"}`)
	}
}
