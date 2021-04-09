package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func handleCheckTCP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	mainTimeout := monTimeout
	if r.Header.Get("X-Timeout") != "" {
		i, err := strconv.ParseInt(r.Header.Get("X-Timeout"), 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Could not parse X-Timeout: %v", err))
			return
		}
		mainTimeout = time.Second * time.Duration(i)
	}

	if vars["ip"] == "" {
		userErrorJSON(w, fmt.Errorf("No IP Address Specified"))
		return
	}
	if vars["port"] == "" {
		userErrorJSON(w, fmt.Errorf("No Port number Specified"))
		return
	}
	port, err := strconv.Atoi(vars["port"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("Could not parse port number: %v", err))
		return
	}

	ip, err := parseIP(vars["ip"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("Could not parse IP: %v", err))
		return
	}

	host := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	network := "tcp4"
	dialer := net.Dialer{
		Timeout: monTimeout,
	}
	if strings.Index(ip.String(), ":") != -1 {
		network = "tcp6"
	}
	ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
	defer cancel()
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, host)
	duration := time.Since(start)

	if err != nil {
		outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
		return
	}
	defer conn.Close()
	outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
}
