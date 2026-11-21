package main

import (
	"github.com/turansec/edr/backend/internal/edr"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	token := os.Getenv("EDR_DEV_TOKEN")
	if len(token) < 16 {
		log.Fatal("set EDR_DEV_TOKEN (at least 16 characters); development-only shared bearer authentication")
	}
	addr := os.Getenv("EDR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	s := &edr.Server{Store: edr.NewStore(), Token: token, WebDir: edr.WebPath()}
	server := http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 45 * time.Second}
	log.Printf("TuranSec EDR lab server on http://%s (in-memory data only)", addr)
	log.Fatal(server.ListenAndServe())
}
