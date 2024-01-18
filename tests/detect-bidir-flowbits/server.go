package main

import (
	"fmt"
	"net/http"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Jetty")
		w.WriteHeader(http.StatusInternalServerError)
		content := "org.openqa.selenium.WebDriverException: unknown error: Chrome failed to start: exited normally."
		content = content + `unknown error: DevToolsActivePort file doesn't exist)\n  (The process started from chrome location`
		n, err := w.Write([]byte(content))
		fmt.Printf("lola %v %v\n", n, err)
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: handler,
	}

	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	err := server.ListenAndServe()
	fmt.Printf("lol %s", err)
}
