package httpx

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// Recorder wraps a ResponseWriter and remembers what the handler did with it,
// so the access log can report the real status and byte count without every
// stage having to cooperate.
//
// It forwards Flush and Hijack to the underlying writer when those are
// available, because a gateway that silently breaks streaming or WebSocket
// upgrades is worse than one that never advertised support.
type Recorder struct {
	http.ResponseWriter

	status  int
	written int64
	recErr  error
}

// NewRecorder wraps w. A Recorder is never nested: if w already is one, it is
// returned unchanged so the outermost wrapper stays the single source of
// truth.
func NewRecorder(w http.ResponseWriter) *Recorder {
	if existing, ok := w.(*Recorder); ok {
		return existing
	}
	return &Recorder{ResponseWriter: w}
}

// WriteHeader records the status and forwards it. Only the first call counts,
// matching net/http's own behaviour.
func (r *Recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

// Write records the byte count, defaulting the status to 200 when a handler
// writes a body without ever calling WriteHeader.
func (r *Recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.written += int64(n)
	return n, err
}

// Status returns the status sent to the client, or 0 when nothing was written.
func (r *Recorder) Status() int { return r.status }

// Written returns the number of body bytes sent to the client.
func (r *Recorder) Written() int64 { return r.written }

// Err returns the first error recorded during the request.
func (r *Recorder) Err() error { return r.recErr }

// Flush implements http.Flusher when the underlying writer supports it.
func (r *Recorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker when the underlying writer supports it.
func (r *Recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("httpx: underlying ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}

// Unwrap exposes the wrapped writer for http.ResponseController.
func (r *Recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// StatusFrom reports the status recorded by the Recorder wrapping w, or 0
// when w is not a Recorder.
func StatusFrom(w http.ResponseWriter) int {
	if r, ok := w.(*Recorder); ok {
		return r.Status()
	}
	return 0
}

// ErrorFrom returns the error recorded by the Recorder wrapping w.
func ErrorFrom(w http.ResponseWriter) error {
	if r, ok := w.(*Recorder); ok {
		return r.Err()
	}
	return nil
}

// RecordError attaches err to the Recorder wrapping w, keeping the first
// error recorded. A no-op when w is not a Recorder.
func RecordError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if r, ok := w.(*Recorder); ok && r.recErr == nil {
		r.recErr = err
	}
}

// RecordStatus overwrites the recorded status. The proxy uses it to report
// the upstream's status, which is what the caller actually saw, rather than
// the 200 the ResponseWriter was handed.
func RecordStatus(w http.ResponseWriter, status int) {
	if status <= 0 {
		return
	}
	if r, ok := w.(*Recorder); ok {
		r.status = status
	}
}
