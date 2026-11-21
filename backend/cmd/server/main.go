package main

import (
	"github.com/turansec/edr/backend/internal/edr"
	"log"
	"errors"
	"net"
	"strconv"
	"net/http"
	"os"
	"time"
)

// labListenAddr fails closed if an operator tries to expose the shared-token,
// in-memory development API on a routable interface. Use an SSH tunnel or
// dedicated authenticated TLS proxy instead of binding this listener publicly.
func labListenAddr(value string) (string, error) {
	if value == "" { value = "127.0.0.1:8080" }
	host, portText, err := net.SplitHostPort(value)
	if err != nil { return "", errors.New("development API requires an explicit loopback IP:port") }
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("development API may listen only on numeric loopback IP addresses")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("development API requires a valid nonzero port")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func main() {
	token := os.Getenv("EDR_DEV_TOKEN")
	if len(token) < 16 {
		log.Fatal("set EDR_DEV_TOKEN (at least 16 characters); development-only shared bearer authentication")
	}
	addr, err := labListenAddr(os.Getenv("EDR_ADDR"))
	if err != nil { log.Fatal(err) }
	s := &edr.Server{Store: edr.NewStore(), Token: token, WebDir: edr.WebPath()}
	server := http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 45 * time.Second}
	log.Printf("TuranSec EDR lab server on http://%s (in-memory data only)", addr)
	log.Fatal(server.ListenAndServe())
}
