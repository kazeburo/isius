package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/jessevdk/go-flags"
	"github.com/kazeburo/isius/accesslog"
	"github.com/lestrrat-go/server-starter/listener"
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

	var l net.Listener
	listens, err := listener.ListenAll()
	if err != nil && err != listener.ErrNoListeningTarget {
		log.Printf("Failed to initialize listener:%v", err)
		return UNKNOWN
	}

	if len(listens) < 1 {
		// Fallback if not running under Server::Starter
		l, err = net.Listen("tcp", fmt.Sprintf("%s:%s", opts.Listen, opts.Port))
		if err != nil {
			log.Printf("Failed to listen to port %s:%s :%v", opts.Listen, opts.Port, err)
			return CRITICAL
		}
	} else {
		l = listens[0]
	}

	if err := server.Serve(l); err != http.ErrServerClosed {
		log.Printf("Error in server.Serve: %v", err)
		return CRITICAL
	}

	<-idleConnsClosed

	return OK
}
