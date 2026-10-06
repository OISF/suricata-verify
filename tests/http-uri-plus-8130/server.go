package main

import (
	"fmt"
	"net/http"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Jetty")
		r.ParseForm()
		_, _ = w.Write([]byte(fmt.Sprintf("form: %#+v\n", r.Form)))
		_, _ = w.Write([]byte(fmt.Sprintf("uri:%s\n", r.RequestURI)))
		_, _ = w.Write([]byte(fmt.Sprintf("path:%s\n", r.URL.Path)))
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: handler,
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
