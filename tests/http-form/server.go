package main

import (
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		content := r.Form.Encode()
		_, _ = w.Write([]byte(content))
	})

	h2s := &http2.Server{}

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: h2c.NewHandler(handler, h2s),
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
