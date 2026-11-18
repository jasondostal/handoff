// Package server is handoff's HTTP side: public share pages under /s/
// and the owner's admin pages under /admin/.
package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"handoff/internal/store"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web
var webFS embed.FS

type Config struct {
	Root    string // the shared folder; links can only point inside it
	BaseURL string // public origin links are built on, e.g. https://share.example.com

	// Admin access. At least one must be set.
	AdminPasswordHash string // bcrypt hash; enables the built-in login page
	AdminProxySecret  string // a reverse proxy that has already authenticated the owner sends this in X-Proxy-Auth

	TrustProxy         bool  // take the client IP from X-Real-IP / X-Forwarded-For
	DefaultUploadLimit int64 // preselected allowance for new upload links
	Owner              string // optional: "Ask <Owner> for a new link"
	Version            string
}

type Server struct {
	cfg    Config
	st     *store.Store
	root   *os.Root
	secret []byte
	tmpl   map[string]*template.Template
	log    *slog.Logger
	secure bool // cookies get the Secure flag
	now    func() time.Time
	logins *limiter
}

func New(cfg Config, st *store.Store, log *slog.Logger) (*Server, error) {
	if cfg.AdminPasswordHash == "" && cfg.AdminProxySecret == "" {
		return nil, errors.New("set an admin password or a proxy secret, or no one can create links")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("base URL %q must look like https://share.example.com", cfg.BaseURL)
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.DefaultUploadLimit <= 0 {
		cfg.DefaultUploadLimit = 1 << 30
	}
	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("share root: %w", err)
	}
	secret, err := st.Secret()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, st: st, root: root, secret: secret, log: log,
		secure: u.Scheme == "https", now: time.Now, logins: newLimiter(10, 15*time.Minute)}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() error { return s.root.Close() }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/icon.svg", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, http.StatusOK, "home", nil)
	})

	s.publicRoutes(mux)
	s.adminRoutes(mux)

	var h http.Handler = mux
	h = http.NewCrossOriginProtection().Handler(h) // refuses cross-site POSTs
	h = s.headers(h)
	return h
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// headers sets the strict defaults every response gets.
func (s *Server) headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: no-referrer makes browsers send
		// "Origin: null" on form posts, which breaks CSRF checks. Either
		// way the token never leaves in a Referer to another site.
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("X-Robots-Tag", "noindex, nofollow")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// ---- templates ----

var pages = []string{"home", "gone", "notfound", "unlock", "share_file", "share_dir",
	"admin_login", "admin_files", "admin_links", "admin_link", "admin_share", "error"}

func (s *Server) loadTemplates() error {
	funcs := template.FuncMap{
		"bytes":   humanBytes,
		"date":    func(t time.Time) string { return t.Local().Format("Jan 2, 2006") },
		"when":    s.when,
		"expires": s.expiresText,
		"esc":     escapePath,
		"preview": canPreview,
		"isoDate": func(v any) string {
			if t, ok := v.(*time.Time); ok && t != nil {
				return t.Local().Format("2006-01-02")
			}
			return ""
		},
		"version": func() string { return s.cfg.Version },
		"owner":   func() string { return s.cfg.Owner },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
	}
	s.tmpl = map[string]*template.Template{}
	for _, p := range pages {
		t, err := template.New("").Funcs(funcs).ParseFS(webFS, "web/templates/base.html", "web/templates/"+p+".html")
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		s.tmpl[p] = t
	}
	return nil
}

func (s *Server) render(w http.ResponseWriter, status int, page string, data any) {
	if data == nil {
		data = map[string]any{}
	}
	var buf bytes.Buffer
	if err := s.tmpl[page].ExecuteTemplate(&buf, "base", data); err != nil {
		s.log.Error("render", "page", page, "err", err)
		http.Error(w, "page failed to render", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "error", map[string]any{"Status": status, "Message": msg})
}

// ---- small helpers ----

func escapePath(rel string) string {
	if rel == "" {
		return ""
	}
	segs := strings.Split(rel, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	if v >= 999.5 && exp < 5 { // 1023.9 MB reads better as 1.0 GB
		v /= unit
		exp++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %cB", v, "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %cB", v, "KMGTPE"[exp])
}

func (s *Server) when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := s.now().Sub(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
	return t.Local().Format("Jan 2, 2006")
}

func (s *Server) expiresText(t *time.Time) string {
	if t == nil {
		return "Never expires"
	}
	if !s.now().Before(*t) {
		return "Expired " + t.Local().Format("Jan 2, 2006")
	}
	return "Expires " + t.Local().Format("Jan 2, 2006")
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- signed cookies ----

func (s *Server) sign(parts ...string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// signedValue is "<unix expiry>.<mac>" over purpose+expiry.
func (s *Server) signedValue(purpose string, ttl time.Duration) string {
	exp := strconv.FormatInt(s.now().Add(ttl).Unix(), 10)
	return exp + "." + s.sign(purpose, exp)
}

func (s *Server) checkSigned(purpose, v string) bool {
	exp, mac, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || s.now().Unix() >= n {
		return false
	}
	want := s.sign(purpose, exp)
	return subtle.ConstantTimeCompare([]byte(mac), []byte(want)) == 1
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
}

// HashPassword is used by the CLI and the admin share form.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
