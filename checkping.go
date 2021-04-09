package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	ping "github.com/digineo/go-ping"
	"github.com/gorilla/mux"
)

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
