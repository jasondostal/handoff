package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jasondostal/handoff/internal/store"
)

const adminTTL = 12 * time.Hour

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", s.loginPage)
	mux.HandleFunc("POST /admin/login", smallBody(s.login))
	mux.HandleFunc("POST /admin/logout", s.logout)

	a := func(pattern string, h http.HandlerFunc) {
		if strings.HasPrefix(pattern, "POST ") && pattern != "POST /admin/upload/{path...}" {
			h = smallBody(h)
		}
		mux.Handle(pattern, s.requireAdmin(h))
	}
	a("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/files/", http.StatusSeeOther)
	})
	a("GET /admin/files/{path...}", s.adminFiles)
	a("GET /admin/view/{path...}", s.adminOpen(true))
	a("GET /admin/download/{path...}", s.adminOpen(false))
	a("POST /admin/upload/{path...}", s.adminUpload)
	a("POST /admin/mkdir/{path...}", s.adminMkdir)
	a("POST /admin/delete/{path...}", s.adminDelete)
	a("GET /admin/share", s.adminShareForm)
	a("GET /admin/links", s.adminLinks)
	a("POST /admin/links", s.adminCreateLink)
	a("GET /admin/links/{id}", s.adminLink)
	a("POST /admin/links/{id}/expiry", s.adminSetExpiry)
	a("POST /admin/links/{id}/label", s.adminSetLabel)
	a("POST /admin/links/{id}/revoke", s.adminRevoke)
	a("POST /admin/links/{id}/delete", s.adminDeleteLink)
}

func (s *Server) isAdmin(r *http.Request) bool {
	if sec := s.cfg.AdminProxySecret; sec != "" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Proxy-Auth")), []byte(sec)) == 1 {
			return true
		}
	}
	if s.cfg.AdminPasswordHash != "" {
		if c, err := r.Cookie("ha"); err == nil && s.checkSigned("admin", c.Value) {
			return true
		}
	}
	return false
}

func (s *Server) requireAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isAdmin(r) {
			w.Header().Set("Cache-Control", "no-store")
			h.ServeHTTP(w, r)
			return
		}
		if s.cfg.AdminPasswordHash == "" {
			s.fail(w, http.StatusForbidden, "The admin pages are only reachable through the proxy.")
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		s.fail(w, http.StatusForbidden, "Sign in first.")
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminPasswordHash == "" {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "admin_login", nil)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminPasswordHash == "" {
		s.fail(w, http.StatusNotFound, "Password sign-in is off.")
		return
	}
	ip := s.clientIP(r)
	if !s.logins.allow(ip, s.now()) {
		s.render(w, http.StatusTooManyRequests, "admin_login", map[string]any{"Error": "Too many tries. Wait 15 minutes."})
		return
	}
	if !checkPassword(s.cfg.AdminPasswordHash, r.FormValue("password")) {
		s.logins.fail(ip, s.now())
		s.log.Warn("admin login failed", "ip", ip)
		s.render(w, http.StatusUnauthorized, "admin_login", map[string]any{"Error": "Wrong password."})
		return
	}
	s.setCookie(w, "ha", s.signedValue("admin", adminTTL), "/admin", adminTTL)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "ha", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// ---- view models ----

type linkView struct {
	*store.Link
	URL    string
	Name   string
	State  string
	Shown  string // path as the owner sees it
	Remain int64
}

func (s *Server) view(l *store.Link) linkView {
	shown := "/" + l.Path
	return linkView{Link: l, URL: s.cfg.BaseURL + "/s/" + l.Token, Name: shareName(l),
		State: l.Status(s.now()), Shown: shown, Remain: max(0, l.UploadLimit-l.UploadedBytes)}
}

func adminCrumbs(rel string) []crumb {
	out := []crumb{{"Shared folder", "/admin/files/"}}
	acc := ""
	if rel != "" {
		for _, seg := range strings.Split(rel, "/") {
			acc = joinRel(acc, seg)
			out = append(out, crumb{seg, "/admin/files/" + escapePath(acc) + "/"})
		}
	}
	return out
}

// ---- files ----

func (s *Server) adminFiles(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such folder.")
		return
	}
	entries, err := list(s.root, rel)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such folder.")
		return
	}
	links, err := s.st.Links()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	active := map[string]int{}
	for _, l := range links {
		if l.Usable(s.now()) {
			active[l.Path]++
		}
	}
	s.render(w, http.StatusOK, "admin_files", map[string]any{
		"Nav": "files", "Rel": rel, "RelEsc": escapePath(rel), "Crumbs": adminCrumbs(rel),
		"Entries": entries, "Active": active, "Here": adminCrumbs(rel)[len(adminCrumbs(rel))-1].Name,
		"Msg": r.URL.Query().Get("msg"),
	})
}

// adminOpen serves one file to the owner: inline for previewable types
// when view is set, otherwise as a download.
func (s *Server) adminOpen(view bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rel, err := cleanRel(r.PathValue("path"))
		if err != nil || rel == "" {
			s.fail(w, http.StatusNotFound, "No such file.")
			return
		}
		f, err := s.root.Open(rel)
		if err != nil {
			s.fail(w, http.StatusNotFound, "No such file.")
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			s.fail(w, http.StatusNotFound, "No such file.")
			return
		}
		serveFile(w, r, fi.Name(), fi.ModTime(), f, view)
	}
}

func adminDirURL(rel, msg string) string {
	u := "/admin/files/"
	if rel != "" {
		u += escapePath(rel) + "/"
	}
	if msg != "" {
		u += "?msg=" + url.QueryEscape(msg)
	}
	return u
}

func (s *Server) adminUpload(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil {
		s.replyErr(w, r, http.StatusNotFound, "No such folder.")
		return
	}
	if fi, err := s.root.Stat(osPath(rel)); err != nil || !fi.IsDir() {
		s.replyErr(w, r, http.StatusNotFound, "No such folder.")
		return
	}
	var names []string
	n, err := s.receive(r, s.root, rel, 1<<50, nil, func(name string, _ int64) { names = append(names, name) })
	if err != nil {
		s.replyErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"saved":%d}`, n)
		return
	}
	http.Redirect(w, r, adminDirURL(rel, fmt.Sprintf("Uploaded %d file(s)", n)), http.StatusSeeOther)
}

func (s *Server) adminMkdir(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.PathValue("path"))
	name, ok := safeName(r.FormValue("name"))
	if err != nil || !ok {
		s.fail(w, http.StatusBadRequest, "That folder name won't work.")
		return
	}
	target := joinRel(rel, name)
	if err := s.root.Mkdir(target, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		s.fail(w, http.StatusBadRequest, "Couldn't make that folder: "+err.Error())
		return
	}
	http.Redirect(w, r, adminDirURL(target, ""), http.StatusSeeOther)
}

// adminDelete removes one file or one empty folder. Never recursive.
func (s *Server) adminDelete(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil || rel == "" {
		s.fail(w, http.StatusBadRequest, "Can't delete that.")
		return
	}
	parent := path.Dir(rel)
	if parent == "." {
		parent = ""
	}
	if err := s.root.Remove(rel); err != nil {
		msg := "Couldn't delete it."
		if fi, serr := s.root.Stat(rel); serr == nil && fi.IsDir() {
			msg = "That folder isn't empty. Delete what's in it first."
		}
		http.Redirect(w, r, adminDirURL(parent, msg), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, adminDirURL(parent, "Deleted "+path.Base(rel)), http.StatusSeeOther)
}

// ---- links ----

var limitChoices = []struct {
	Label string
	Bytes int64
}{
	{"100 MB", 100 << 20}, {"500 MB", 500 << 20}, {"1 GB", 1 << 30}, {"5 GB", 5 << 30}, {"20 GB", 20 << 30}, {"100 GB", 100 << 30},
}

func (s *Server) adminShareForm(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.URL.Query().Get("path"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "Bad path.")
		return
	}
	fi, err := s.root.Stat(osPath(rel))
	if err != nil {
		s.fail(w, http.StatusNotFound, "That isn't there.")
		return
	}
	name := "the whole shared folder"
	if rel != "" {
		name = path.Base(rel)
	}
	s.render(w, http.StatusOK, "admin_share", map[string]any{
		"Nav": "files", "Rel": rel, "Name": name, "IsDir": fi.IsDir(), "Size": fi.Size(),
		"Limits": limitChoices, "DefaultLimit": s.cfg.DefaultUploadLimit,
		"Parent": adminDirURL(parentOf(rel), ""),
	})
}

func parentOf(rel string) string {
	p := path.Dir(rel)
	if p == "." {
		return ""
	}
	return p
}

// parseExpiry reads the expiry picker: a preset, "never", or a date.
func parseExpiry(choice, date string, now time.Time) (*time.Time, error) {
	days := map[string]int{"1d": 1, "7d": 7, "30d": 30, "90d": 90}
	switch {
	case choice == "never":
		return nil, nil
	case days[choice] > 0:
		t := now.Add(time.Duration(days[choice]) * 24 * time.Hour).Truncate(time.Second)
		return &t, nil
	case choice == "date":
		d, err := time.ParseInLocation("2006-01-02", date, time.Local)
		if err != nil {
			return nil, errors.New("pick a date")
		}
		end := d.Add(24*time.Hour - time.Second) // good through the end of that day
		if !end.After(now) {
			return nil, errors.New("pick a date that hasn't passed")
		}
		return &end, nil
	}
	return nil, errors.New("pick when the link should expire")
}

func (s *Server) adminCreateLink(w http.ResponseWriter, r *http.Request) {
	rel, err := cleanRel(r.FormValue("path"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "Bad path.")
		return
	}
	fi, err := s.root.Stat(osPath(rel))
	if err != nil || !(fi.IsDir() || fi.Mode().IsRegular()) {
		s.fail(w, http.StatusNotFound, "That isn't there.")
		return
	}
	exp, err := parseExpiry(r.FormValue("expiry"), r.FormValue("expiry_date"), s.now())
	if err != nil {
		s.fail(w, http.StatusBadRequest, "Expiry: "+err.Error()+".")
		return
	}
	l := &store.Link{Path: rel, Kind: store.KindFile, Mode: store.ModeRead,
		Label: strings.TrimSpace(r.FormValue("label")), ExpiresAt: exp}
	if fi.IsDir() {
		l.Kind = store.KindDir
		if r.FormValue("mode") == "write" {
			l.Mode = store.ModeWrite
			l.UploadLimit, _ = strconv.ParseInt(r.FormValue("upload_limit"), 10, 64)
			if l.UploadLimit <= 0 {
				l.UploadLimit = s.cfg.DefaultUploadLimit
			}
		}
	}
	if pw := r.FormValue("password"); pw != "" {
		if l.PasswordHash, err = HashPassword(pw); err != nil {
			s.fail(w, http.StatusBadRequest, "That password won't work.")
			return
		}
	}
	if err := s.st.CreateLink(l); err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/links/%d?new=1", l.ID), http.StatusSeeOther)
}

func (s *Server) adminLinks(w http.ResponseWriter, r *http.Request) {
	links, err := s.st.Links()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]linkView, len(links))
	for i, l := range links {
		views[i] = s.view(l)
	}
	s.render(w, http.StatusOK, "admin_links", map[string]any{"Nav": "links", "Links": views})
}

func (s *Server) linkFromPath(w http.ResponseWriter, r *http.Request) (*store.Link, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such link.")
		return nil, false
	}
	l, err := s.st.LinkByID(id)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such link.")
		return nil, false
	}
	return l, true
}

func (s *Server) adminLink(w http.ResponseWriter, r *http.Request) {
	l, ok := s.linkFromPath(w, r)
	if !ok {
		return
	}
	events, _ := s.st.Events(l.ID, 200)
	s.render(w, http.StatusOK, "admin_link", map[string]any{
		"Nav": "links", "L": s.view(l), "Events": events, "New": r.URL.Query().Get("new") == "1",
	})
}

func backTo(r *http.Request, l *store.Link) string {
	if r.FormValue("back") == "list" {
		return "/admin/links"
	}
	return fmt.Sprintf("/admin/links/%d", l.ID)
}

func (s *Server) adminSetExpiry(w http.ResponseWriter, r *http.Request) {
	l, ok := s.linkFromPath(w, r)
	if !ok {
		return
	}
	exp, err := parseExpiry(r.FormValue("expiry"), r.FormValue("expiry_date"), s.now())
	if err != nil {
		s.fail(w, http.StatusBadRequest, "Expiry: "+err.Error()+".")
		return
	}
	if err := s.st.SetExpiry(l.ID, exp); err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, backTo(r, l), http.StatusSeeOther)
}

func (s *Server) adminSetLabel(w http.ResponseWriter, r *http.Request) {
	l, ok := s.linkFromPath(w, r)
	if !ok {
		return
	}
	s.st.SetLabel(l.ID, strings.TrimSpace(r.FormValue("label")))
	http.Redirect(w, r, backTo(r, l), http.StatusSeeOther)
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	l, ok := s.linkFromPath(w, r)
	if !ok {
		return
	}
	s.st.Revoke(l.ID)
	http.Redirect(w, r, backTo(r, l), http.StatusSeeOther)
}

func (s *Server) adminDeleteLink(w http.ResponseWriter, r *http.Request) {
	l, ok := s.linkFromPath(w, r)
	if !ok {
		return
	}
	s.st.Delete(l.ID)
	http.Redirect(w, r, "/admin/links", http.StatusSeeOther)
}

// ---- login rate limit ----

type limiter struct {
	mu   sync.Mutex
	max  int
	win  time.Duration
	hits map[string][]time.Time
}

func newLimiter(max int, win time.Duration) *limiter {
	return &limiter{max: max, win: win, hits: map[string][]time.Time{}}
}

func (l *limiter) prune(key string, now time.Time) []time.Time {
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > l.win {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = h
	}
	return h
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, now)) < l.max
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.prune(key, now), now)
}
