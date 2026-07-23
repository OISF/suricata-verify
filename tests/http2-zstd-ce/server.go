package main

import (
	"github.com/klauspost/compress/zstd"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
)

func main() {
	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h["content-encoding"] = []string{"zstd"}
		fw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
		if err != nil {
			fmt.Fprintf(w, "FAIL %s, %v, http: %v", err, r.URL.Path, r.TLS == nil)
		}
		fmt.Fprintf(fw, "zstd works on http2 but I think it needs a long string to have some effect")
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
