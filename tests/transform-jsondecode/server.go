package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Message struct {
	Key    string `json:"key"`
	Other  string `json:"other"`
	Number uint32 `json:"number"`
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg Message
		err := json.NewDecoder(r.Body).Decode(&msg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, err := json.Marshal(msg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(b))
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: handler,
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
