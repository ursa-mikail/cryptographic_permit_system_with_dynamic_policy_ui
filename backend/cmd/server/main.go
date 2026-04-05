package main

import (
	"log"
	"net/http"
	"os"

	"permit-authority/internal/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	srv := api.NewServer()
	addr := ":" + port
	log.Printf("[BOOT] Permit Authority listening on http://0.0.0.0%s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}
