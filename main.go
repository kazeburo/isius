package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	ping "github.com/digineo/go-ping"
	"github.com/gorilla/mux"
	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/isius/accesslog"
	ss "github.com/lestrrat/go-server-starter-listener"
)

const UNKNOWN = 3
const CRITICAL = 2
const WARNING = 1
const OK = 0
const pingTimeout = 1 * time.Second
const pingInterval = 10 * time.Millisecond
const monTimeout = 300 * time.Second

var version string

type res struct {
	Code    int      `json:"code"`
	Message string   `json:"metric"`
	Errors  []string `json:"errors"`
}

type commandOpts struct {
	Version          bool          `short:"v" long:"version" description:"Show version"`
	Listen           string        `short:"l" long:"listen" default:"0.0.0.0" description:"address to bind"`
	Port             string        `short:"p" long:"port" default:"3000" description:"Port number to bind"`
	LogDir           string        `long:"access-log-dir" default:"" description:"directory to store logfiles"`
	LogRotate        int64         `long:"access-log-rotate" default:"30" description:"Number of rotation before remove logs"`
	LogRotateTime    time.Duration `long:"access-log-rotate-time" default:"24h" description:"Interval time between file rotation"`
	ReadTimeout      time.Duration `long:"read-timeout" default:"30s" description:"timeout of reading request"`
	WriteTimeout     time.Duration `long:"write-timeout" default:"90s" description:"timeout of writing response"`
	ShutdownTimeout  time.Duration `long:"shutdown-timeout" default:"1h"  description:"timeout to wait for all connections to be closed."`
	MountAPIOn       string        `long:"mount-api-on" description:"url path to mount api on"`
	DefaultUserAgent string        `long:"default-user-agent" default:"isisu-monitor-agent" description:"default user-agent string for http monitor"`
}

func round(f float64) int64 {
	return int64(math.Round(f)) - 1
}

func parseIP(ip string) (*net.IPAddr, error) {
	if strings.Index(ip, ":") != -1 {
		return net.ResolveIPAddr("ip6", ip)
	}
	return net.ResolveIPAddr("ip4", ip)
}

func outJSON(w http.ResponseWriter, code int, msg string, errors ...error) {
	error_strings := make([]string, 0)
	for _, e := range errors {
		error_strings = append(error_strings, e.Error())
	}
	json, err := json.Marshal(&res{
		code,
		msg,
		error_strings,
	})
	if err != nil {
		log.Printf("%v", err)
		return
	}
	if code > 0 {
		w.WriteHeader(500)
	}
	w.Write(json)
	w.Write([]byte("\n"))
	return
}

func userErrorJSON(w http.ResponseWriter, e error) {
	error_strings := make([]string, 0)
	error_strings = append(error_strings, e.Error())
	json, err := json.Marshal(&res{
		UNKNOWN,
		"bad request",
		error_strings,
	})
	if err != nil {
		log.Printf("%v", err)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write(json)
	w.Write([]byte("\n"))
	return
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK\n"))
}

func handleCheckPing(w http.ResponseWriter, r *http.Request) {
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
	count := 1
	if vars["count"] != "" {
		var err error
		count, err = strconv.Atoi(vars["count"])
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Could not parse count: %v", err))
			return
		}
	}
	interval := pingInterval
	if vars["interval"] != "" {
		var err error
		i, err := strconv.ParseInt(vars["interval"], 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Could not parse interval: %v", err))
			return
		}
		interval = time.Millisecond * time.Duration(i)
	}

	timeout := pingTimeout
	if vars["timeout"] != "" {
		var err error
		i, err := strconv.ParseInt(vars["timeout"], 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("Could not parse timeout: %v", err))
			return
		}
		timeout = time.Millisecond * time.Duration(i)
	}

	ip, err := parseIP(vars["ip"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("Could not parse IP: %v", err))
		return
	}
	var pinger *ping.Pinger
	if strings.Index(ip.String(), ":") != -1 {
		pinger, err = ping.New("", "::")
		if err != nil {
			outJSON(w, CRITICAL, "", fmt.Errorf("Could not create pinger: %v", err))
			return
		}
	} else {
		pinger, err = ping.New("0.0.0.0", "")
		if err != nil {
			outJSON(w, CRITICAL, "", fmt.Errorf("Could not create pinger: %v", err))
			return
		}
	}

	defer pinger.Close()

	var rtts sort.Float64Slice
	errors := make([]error, 0)
	t := float64(0)
	s := 0
	e := 0
	ch := make(chan struct{})
	ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
	defer cancel()
	go func() {
		for i := 0; i < count; i++ {
			if i > 0 {
				time.Sleep(interval)
			}
			rtt, err := pinger.Ping(ip, timeout)
			if err != nil {
				errors = append(errors, err)
				e++
				continue
			}
			rttMilliSec := float64(rtt.Nanoseconds()) / 1000.0 / 1000.0
			rtts = append(rtts, rttMilliSec)
			t += rttMilliSec
			s++
		}
		close(ch)
	}()

	select {
	case <-ch:
		// done all
	case <-ctx.Done():
		// closed by client
		errors = append(errors, fmt.Errorf("Reached timeout: %v", ctx.Err()))
	}

	sort.Sort(rtts)
	msgs := make([]string, 0)
	msgs = append(msgs, fmt.Sprintf("success:%d", s))
	msgs = append(msgs, fmt.Sprintf("error:%d", e))
	if s > 0 {
		msgs = append(msgs, fmt.Sprintf("max:%f", rtts[round(float64(s))]))
		msgs = append(msgs, fmt.Sprintf("average:%f", t/float64(s)))
		msgs = append(msgs, fmt.Sprintf("90_percentile:%f", rtts[round(float64(s)*0.90)]))
	}
	code := OK
	if s == 0 {
		code = CRITICAL
	} else if e > 0 {
		code = WARNING
	}
	outJSON(w, code, strings.Join(msgs, ","), errors...)
}

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

func printVersion() {
	fmt.Printf(`isius %s
Compiler: %s %s
`,
		version,
		runtime.Compiler,
		runtime.Version())
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opts := commandOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		return WARNING
	}

	if opts.Version {
		printVersion()
		return OK
	}

	mount := opts.MountAPIOn
	mount = strings.TrimPrefix(mount, "/")
	mount = "/" + mount
	mount = strings.TrimSuffix(mount, "/")

	handleHTTPCheck := makeHTTPCheckHandler(opts.DefaultUserAgent)

	m := mux.NewRouter()
	m.Handle("/live", http.HandlerFunc(handleHello))
	m.Handle(mount+"/check_ping/{ip}", http.HandlerFunc(handleCheckPing))
	m.Handle(mount+"/check_ping/{count:[0-9]+}/{interval:[0-9]+}/{timeout:[0-9]+}/{ip}", http.HandlerFunc(handleCheckPing))

	m.Handle(mount+"/check_tcp/{ip}/{port:[0-9]+}", http.HandlerFunc(handleCheckTCP))

	m.Handle(mount+"/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{status:[0-9][0-9][0-9]}", http.HandlerFunc(handleHTTPCheck))
	m.Handle(mount+"/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{status:[0-9][0-9][0-9]}/{host}", http.HandlerFunc(handleHTTPCheck))
	m.Handle(mount+"/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{status:[0-9][0-9][0-9]}/{host}/{path:.*}", http.HandlerFunc(handleHTTPCheck))

	al, err := accesslog.New(opts.LogDir, opts.LogRotate, opts.LogRotateTime)
	if err != nil {
		log.Printf("Error in init logger: %v", err)
		return CRITICAL
	}
	handler := al.WrapHandleFunc(m)

	server := http.Server{
		Handler:      handler,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		<-sigChan
		ctx, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
		if es := server.Shutdown(ctx); es != nil {
			log.Printf("Shutdown error: %v", es)
		}
		cancel()
		close(idleConnsClosed)
	}()

	l, err := ss.NewListener()
	if l == nil || err != nil {
		// Fallback if not running under Server::Starter
		l, err = net.Listen("tcp", fmt.Sprintf("%s:%s", opts.Listen, opts.Port))
		if err != nil {
			log.Printf("Failed to listen to port %s:%s :%v", opts.Listen, opts.Port, err)
			return CRITICAL
		}
	}
	if err := server.Serve(l); err != http.ErrServerClosed {
		log.Printf("Error in server.Serve: %v", err)
		return CRITICAL
	}

	<-idleConnsClosed

	return OK
}
