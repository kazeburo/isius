package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func makeTransport(ip *net.IPAddr, port int, vhost string, timeout time.Duration) http.RoundTripper {
	baseDialFunc := (&net.Dialer{
		Timeout: timeout,
	}).DialContext
	network := "tcp4"
	if strings.Index(ip.String(), ":") != -1 {
		network = "tcp6"
	}
	dialFunc := func(ctx context.Context, _, _ string) (net.Conn, error) {
		address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		return baseDialFunc(ctx, network, address)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if vhost != "" {
		servername, _, err := net.SplitHostPort(vhost)
		if err != nil {
			servername = vhost
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         servername,
		}
	}

	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialFunc,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		// self-customized values
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}
}

func makeHTTPCheckHandler(defaultUA string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if vars["status"] == "" {
			userErrorJSON(w, fmt.Errorf("No Status code Specified"))
			return
		}
		expectedStatus, err := strconv.Atoi(vars["status"])
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Could not parse status number: %v", err))
			return
		}

		if vars["method"] == "" {
			userErrorJSON(w, fmt.Errorf("No HTTP method code Specified"))
			return
		}
		method := strings.ToUpper(vars["method"])

		vhost := vars["host"]
		if vhost == "-" {
			vhost = ip.String()
		}
		host := net.JoinHostPort(vhost, fmt.Sprintf("%d", port))
		path := vars["path"]
		path = "/" + path

		schema := "http"
		if vars["http_scheme"] == "check_https" {
			schema = "https"
		}
		uri := fmt.Sprintf("%s://%s%s", schema, host, path)
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}

		ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
		defer cancel()

		var b bytes.Buffer
		req, err := http.NewRequestWithContext(
			ctx,
			method,
			uri,
			&b,
		)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Failed create request: %v", err))
			return
		}
		ua := r.UserAgent()
		if ua == "" {
			ua = defaultUA
		}
		req.Header.Set("User-Agent", ua)

		transport := makeTransport(ip, port, vars["host"], mainTimeout)
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		start := time.Now()
		res, err := client.Do(req)
		duration := time.Since(start)

		if err != nil {
			outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
			return
		}

		defer res.Body.Close()
		_, err = io.Copy(ioutil.Discard, res.Body)
		if res.StatusCode != expectedStatus {
			outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), fmt.Errorf("status code %d not match %d", res.StatusCode, expectedStatus))
			return
		}

		outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
	}
}
