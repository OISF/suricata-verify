package main

import (
	"compress/flate"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
)

func main() {
	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h["content-encoding"] = []string{"deflate"}
		fw, err := flate.NewWriter(w, 1)
		if err != nil {
			fmt.Fprintf(w, "FAIL %s, %v, http: %v", err, r.URL.Path, r.TLS == nil)
		}
		fmt.Fprintf(fw, "Hello, %v, http: %v", r.URL.Path, r.TLS == nil)
		fw.Flush()
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: h2c.NewHandler(handler, h2s),
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
