package main

import (
	"fmt"
	"net/http"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Jetty")
		w.Header().Set("Content-encoding", "identity")
		content := "identity content-encoding works"
		_, _ = w.Write([]byte(content))
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: handler,
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
