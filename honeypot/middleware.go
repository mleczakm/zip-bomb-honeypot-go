package honeypot

import (
	"net/http"
	"strconv"
)

// Middleware intercepts requests whose URL paths match common scanner probes.
// OnProbe, when non-nil, is called synchronously before the decoy is served.
type Middleware struct {
	next    http.Handler
	matcher Matcher
	onProbe func(*http.Request)
}

// New returns middleware that serves a harmless, bounded ZIP decoy for matching
// paths and delegates all other requests to next. A nil next handler becomes
// http.NotFoundHandler.
func New(next http.Handler, onProbe func(*http.Request)) *Middleware {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return &Middleware{next: next, matcher: Matcher{}, onProbe: onProbe}
}

// ServeHTTP implements http.Handler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !m.matcher.Match(r.URL.Path) {
		m.next.ServeHTTP(w, r)
		return
	}
	if m.onProbe != nil {
		m.onProbe(r)
	}
	archive, err := decoyArchive()
	if err != nil {
		http.Error(w, "honeypot unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"probe-decoy.zip\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(archive)
	}
}
