package accesslog

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AccessLog :
type AccessLog struct {
	logger *zap.Logger
}

func logWriter(logDir string, logRotate uint, logRotateTime time.Duration) (io.Writer, error) {
	if logDir == "stdout" {
		return os.Stdout, nil
	} else if logDir == "" {
		return os.Stderr, nil
	} else if logDir == "none" {
		return nil, nil
	}
	logFile := logDir
	linkName := logDir
	if !strings.HasSuffix(logDir, "/") {
		logFile += "/"
		linkName += "/"

	}
	logFile += "access_log.%Y%m%d%H%M"
	linkName += "current"

	rl, err := rotatelogs.New(
		logFile,
		rotatelogs.WithLinkName(linkName),
		rotatelogs.WithMaxAge(-1),
		rotatelogs.WithRotationCount(logRotate),
		rotatelogs.WithRotationTime(logRotateTime),
	)
	if err != nil {
		return nil, errors.Wrap(err, "rotatelogs.New failed")
	}
	return rl, nil
}

// New :
func New(logDir string, logRotate uint, logRotateTime time.Duration) (*AccessLog, error) {
	w, err := logWriter(logDir, logRotate, logRotateTime)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return &AccessLog{}, nil
	}

	encoderConfig := zapcore.EncoderConfig{
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	logger := zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(w),
			zapcore.InfoLevel,
		),
	)
	return &AccessLog{
		logger: logger,
	}, nil
}

// WrapHandleFunc :
func (al *AccessLog) WrapHandleFunc(h http.Handler) http.Handler {
	if al.logger == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := WrapWriter(w)
		defer func() {
			end := time.Now()
			ptime := end.Sub(start)
			remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteAddr = r.RemoteAddr
			}

			al.logger.Info(
				"-",
				zap.String("time", start.Format("2006/01/02 15:04:05 MST")),
				zap.String("remote_addr", remoteAddr),
				zap.String("method", r.Method),
				zap.String("uri", r.URL.Path),
				zap.Int("status", ww.GetCode()),
				zap.Int("size", ww.GetSize()),
				zap.String("ua", r.UserAgent()),
				zap.Float64("ptime", ptime.Seconds()),
				zap.String("host", r.Host),
				zap.String("xff", r.Header.Get("X-Forwarded-For")),
				zap.Strings("errors", ww.GetErrors()),
			)
		}()
		h.ServeHTTP(ww, r)
	})
}

// Writer :
type Writer struct {
	w    http.ResponseWriter
	size int
	code int
	err  []string
}

// WrapWriter :
func WrapWriter(w http.ResponseWriter) *Writer {
	return &Writer{
		w:    w,
		code: 200,
	}
}

func (w *Writer) SetErrors(s []string) {
	w.err = s
}

func (w *Writer) GetErrors() []string {
	if w.err != nil {
		return w.err
	}
	var errs = []string{}
	return errs
}

// Header :
func (w *Writer) Header() http.Header {
	return w.w.Header()
}

// Write :
func (w *Writer) Write(b []byte) (int, error) {
	w.size += len(b)
	return w.w.Write(b)
}

// WriteHeader :
func (w *Writer) WriteHeader(statusCode int) {
	w.code = statusCode
	w.w.WriteHeader(statusCode)
}

// GetCode :
func (w *Writer) GetCode() int {
	return w.code
}

// GetSize :
func (w *Writer) GetSize() int {
	return w.size
}
