package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"handoff/internal/store"
)

func (s *Server) publicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /s/{token}", s.sharePage)
	mux.HandleFunc("GET /s/{token}/d/{path...}", s.shareDir)
	mux.HandleFunc("GET /s/{token}/f/{path...}", s.shareDownload)
	mux.HandleFunc("GET /s/{token}/zip/{path...}", s.shareZip)
	mux.HandleFunc("POST /s/{token}/upload/{path...}", s.shareUpload)
	mux.HandleFunc("POST /s/{token}/mkdir/{path...}", smallBody(s.shareMkdir))
	mux.HandleFunc("POST /s/{token}/unlock", smallBody(s.shareUnlock))
}

const unlockTTL = 12 * time.Hour

func unlockCookie(l *store.Link) string { return "hu" + strconv.FormatInt(l.ID, 36) }

func (s *Server) unlockPurpose(l *store.Link) string {
	// Includes the hash, so changing a link's password signs everyone out.
	return "unlock\x00" + l.Token + "\x00" + l.PasswordHash
}

func (s *Server) unlocked(r *http.Request, l *store.Link) bool {
	if l.PasswordHash == "" {
		return true
	}
	c, err := r.Cookie(unlockCookie(l))
	return err == nil && s.checkSigned(s.unlockPurpose(l), c.Value)
}

// gate looks up the link and stops the request (writing the response) if
// it doesn't exist, has expired or been revoked, or still needs its
// password. Every public handler goes through it.
func (s *Server) gate(w http.ResponseWriter, r *http.Request, needUnlock bool) (*store.Link, bool) {
	token := r.PathValue("token")
	var l *store.Link
	var err error
	if len(token) >= 16 && len(token) <= 64 {
		l, err = s.st.LinkByToken(token)
	} else {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return nil, false
	}
	if err != nil {
		s.log.Error("link lookup", "err", err)
		s.fail(w, http.StatusInternalServerError, "Something went wrong on our side.")
		return nil, false
	}
	if !l.Usable(s.now()) {
		s.render(w, http.StatusGone, "gone", map[string]any{"Status": l.Status(s.now())})
		return nil, false
	}
	if needUnlock && !s.unlocked(r, l) {
		if r.Method == http.MethodGet {
			s.render(w, http.StatusUnauthorized, "unlock", map[string]any{"Token": l.Token})
		} else {
			s.replyErr(w, r, http.StatusForbidden, "This link needs its password first.")
		}
		return nil, false
	}
	return l, true
}

func (s *Server) record(r *http.Request, l *store.Link, kind, p string, n int64) {
	if err := s.st.Record(store.Event{LinkID: l.ID, Kind: kind, Path: p, Bytes: n,
		IP: s.clientIP(r), UA: r.UserAgent()}); err != nil {
		s.log.Error("record event", "err", err)
	}
}

// dirRoot opens the folder a dir link points at. The caller closes it.
func (s *Server) dirRoot(w http.ResponseWriter, l *store.Link) (*os.Root, bool) {
	if l.Kind != store.KindDir {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return nil, false
	}
	sub, err := s.root.OpenRoot(osPath(l.Path))
	if err != nil {
		s.fail(w, http.StatusNotFound, "This shared folder isn't there anymore.")
		return nil, false
	}
	return sub, true
}

func shareName(l *store.Link) string {
	if l.Path == "" {
		return "Shared files"
	}
	return path.Base(l.Path)
}

type crumb struct{ Name, URL string }

func (s *Server) sharePage(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	if l.Kind == store.KindDir {
		s.renderDir(w, r, l, "")
		if r.URL.Query().Get("up") == "" { // not the reload after an upload
			s.record(r, l, "view", "", 0)
		}
		return
	}
	f, err := s.root.Open(l.Path)
	if err != nil {
		s.fail(w, http.StatusNotFound, "This shared file isn't there anymore.")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		s.fail(w, http.StatusNotFound, "This shared file isn't there anymore.")
		return
	}
	s.record(r, l, "view", "", 0)
	name := path.Base(l.Path)
	s.render(w, http.StatusOK, "share_file", map[string]any{
		"Name": name, "Size": fi.Size(), "ModTime": fi.ModTime(), "Link": l,
		"DownloadURL": "/s/" + l.Token + "/f/" + escapePath(name),
	})
}

func (s *Server) shareDir(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return
	}
	s.renderDir(w, r, l, rel)
}

func (s *Server) renderDir(w http.ResponseWriter, r *http.Request, l *store.Link, rel string) {
	sub, ok := s.dirRoot(w, l)
	if !ok {
		return
	}
	defer sub.Close()
	entries, err := list(sub, rel)
	if err != nil {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return
	}
	base := "/s/" + l.Token
	crumbs := []crumb{{shareName(l), base}}
	if rel != "" {
		acc := ""
		for _, seg := range strings.Split(rel, "/") {
			acc = joinRel(acc, seg)
			crumbs = append(crumbs, crumb{seg, base + "/d/" + escapePath(acc)})
		}
	}
	remaining := l.UploadLimit - l.UploadedBytes
	if remaining < 0 {
		remaining = 0
	}
	uploaded, _ := strconv.Atoi(r.URL.Query().Get("up"))
	s.render(w, http.StatusOK, "share_dir", map[string]any{
		"Link": l, "Base": base, "Rel": rel, "RelEsc": escapePath(rel), "Crumbs": crumbs,
		"Entries": entries, "CanWrite": l.CanWrite(), "Remaining": remaining,
		"Uploaded": uploaded, "Here": crumbs[len(crumbs)-1].Name,
	})
}

func (s *Server) shareDownload(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	var f *os.File
	var logPath string
	if l.Kind == store.KindFile {
		// A file link serves exactly one file, whatever name is asked for
		// at most the file's own (the name is only there for the browser).
		if p := r.PathValue("path"); p != "" && p != path.Base(l.Path) {
			s.render(w, http.StatusNotFound, "notfound", nil)
			return
		}
		var err error
		if f, err = s.root.Open(l.Path); err != nil {
			s.fail(w, http.StatusNotFound, "This shared file isn't there anymore.")
			return
		}
	} else {
		rel, err := cleanRel(r.PathValue("path"))
		if err != nil || rel == "" {
			s.render(w, http.StatusNotFound, "notfound", nil)
			return
		}
		sub, ok := s.dirRoot(w, l)
		if !ok {
			return
		}
		defer sub.Close()
		if f, err = sub.Open(rel); err != nil {
			s.render(w, http.StatusNotFound, "notfound", nil)
			return
		}
		logPath = rel
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return
	}
	// Count a download once, not once per resumed range.
	if rg := r.Header.Get("Range"); rg == "" || strings.HasPrefix(rg, "bytes=0-") {
		s.record(r, l, "download", logPath, fi.Size())
	}
	serveFile(w, r, fi.Name(), fi.ModTime(), f, false)
}

// Types the browser may be told about. Everything else is
// application/octet-stream. All of them are sent as attachments in a
// sandbox, so an uploaded .html or .svg can never run on this origin.
var safeTypes = map[string]string{
	".pdf": "application/pdf", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
	".gif": "image/gif", ".webp": "image/webp", ".heic": "image/heic", ".txt": "text/plain; charset=utf-8",
	".csv": "text/csv; charset=utf-8", ".zip": "application/zip", ".mp4": "video/mp4", ".mov": "video/quicktime",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4",
	".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt": "application/vnd.ms-powerpoint", ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

func disposition(kind, name string) string {
	if v := mime.FormatMediaType(kind, map[string]string{"filename": name}); v != "" {
		return v
	}
	return kind
}

// Types the owner can open in the browser from the admin pages instead of
// downloading. Never HTML, SVG or anything else that can carry script.
var previewTypes = map[string]bool{
	".pdf": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true,
	".txt": true, ".csv": true, ".mp4": true, ".mov": true, ".mp3": true, ".m4a": true,
}

func canPreview(name string) bool { return previewTypes[strings.ToLower(path.Ext(name))] }

// serveFile sends a file as a download, or inline when inline is set and
// the type is on the preview list. Either way the type comes from the
// extension (with nosniff), so a file can never be read as a web page.
func serveFile(w http.ResponseWriter, r *http.Request, name string, mod time.Time, rs io.ReadSeeker, inline bool) {
	ext := strings.ToLower(path.Ext(name))
	ct, ok := safeTypes[ext]
	if !ok {
		ct = "application/octet-stream"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	switch {
	case inline && ext == ".pdf":
		// Browsers' PDF viewers refuse to run inside a CSP sandbox. The
		// type is pinned to application/pdf, so there is no page to guard.
		h.Set("Content-Disposition", disposition("inline", name))
		h.Del("Content-Security-Policy")
	case inline && previewTypes[ext]:
		h.Set("Content-Disposition", disposition("inline", name))
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'")
	default:
		h.Set("Content-Disposition", disposition("attachment", name))
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	}
	http.ServeContent(w, r, name, mod, rs)
}

// smallBody caps the request body of plain form posts. Only the upload
// handlers take big bodies; without this a multipart post to any other
// form could spool gigabytes to a temp file before being turned away.
func smallBody(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		h(w, r)
	}
}

func (s *Server) shareZip(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return
	}
	sub, ok := s.dirRoot(w, l)
	if !ok {
		return
	}
	defer sub.Close()
	if fi, err := sub.Stat(osPath(rel)); err != nil || !fi.IsDir() {
		s.render(w, http.StatusNotFound, "notfound", nil)
		return
	}
	name := shareName(l)
	if rel != "" {
		name = path.Base(rel)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", disposition("attachment", name+".zip"))
	s.record(r, l, "zip", rel, 0)
	if err := writeZip(w, sub, rel); err != nil {
		s.log.Warn("zip", "err", err)
	}
}

// ---- uploads ----

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func (s *Server) replyErr(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": msg})
		return
	}
	s.fail(w, status, msg)
}

// receive streams every file part of a multipart upload into dir. Nothing
// is buffered in memory or a temp dir; each file goes straight to disk.
// reserve, if set, must accept each file's size or the file is removed.
func (s *Server) receive(r *http.Request, root *os.Root, dir string, limit int64,
	reserve func(n int64) (bool, error), saved func(name string, n int64)) (int, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return 0, errBadUpload
	}
	count := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return count, errTooBig
			}
			return count, errBadUpload
		}
		if part.FormName() != "files" || part.FileName() == "" {
			part.Close()
			continue
		}
		name, ok := safeName(part.FileName())
		if !ok {
			part.Close()
			continue
		}
		final, n, err := saveNew(root, dir, name, part, limit)
		part.Close()
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return count, errTooBig
			}
			return count, err
		}
		if reserve != nil {
			ok, rerr := reserve(n)
			if rerr != nil || !ok {
				root.Remove(joinRel(dir, final))
				if rerr != nil {
					return count, rerr
				}
				return count, errTooBig
			}
		}
		limit -= n
		count++
		saved(final, n)
	}
}

var errBadUpload = errors.New("that upload didn't come through properly")

func (s *Server) shareUpload(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	if !l.CanWrite() {
		s.replyErr(w, r, http.StatusForbidden, "This link is view-only.")
		return
	}
	rel, err := cleanRel(r.PathValue("path"))
	if err != nil {
		s.replyErr(w, r, http.StatusNotFound, "That folder doesn't exist.")
		return
	}
	sub, ok := s.dirRoot(w, l)
	if !ok {
		return
	}
	defer sub.Close()
	if fi, err := sub.Stat(osPath(rel)); err != nil || !fi.IsDir() {
		s.replyErr(w, r, http.StatusNotFound, "That folder doesn't exist.")
		return
	}
	remaining := l.UploadLimit - l.UploadedBytes
	if remaining <= 0 {
		s.replyErr(w, r, http.StatusRequestEntityTooLarge, "This link has used up its upload allowance.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, remaining+1<<20) // +1 MiB for multipart framing
	var names []string
	n, err := s.receive(r, sub, rel, remaining,
		func(n int64) (bool, error) { return s.st.ReserveUpload(l.ID, n) },
		func(name string, n int64) {
			names = append(names, name)
			s.record(r, l, "upload", joinRel(rel, name), n)
		})
	if err != nil {
		status, msg := http.StatusBadRequest, err.Error()
		if errors.Is(err, errTooBig) {
			status = http.StatusRequestEntityTooLarge
			msg = "That's more than this link can take (" + humanBytes(remaining) + " left)."
		} else if !errors.Is(err, errBadUpload) {
			s.log.Error("upload", "err", err)
			status, msg = http.StatusInternalServerError, "The upload couldn't be saved."
		}
		if n > 0 {
			msg += " " + strconv.Itoa(n) + " file(s) before that were saved."
		}
		s.replyErr(w, r, status, msg)
		return
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"saved": names})
		return
	}
	http.Redirect(w, r, dirURL(l, rel)+"?up="+strconv.Itoa(n), http.StatusSeeOther)
}

func dirURL(l *store.Link, rel string) string {
	if rel == "" {
		return "/s/" + l.Token
	}
	return "/s/" + l.Token + "/d/" + escapePath(rel)
}

func (s *Server) shareMkdir(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, true)
	if !ok {
		return
	}
	if !l.CanWrite() {
		s.replyErr(w, r, http.StatusForbidden, "This link is view-only.")
		return
	}
	rel, err := cleanRel(r.PathValue("path"))
	name, okName := safeName(r.FormValue("name"))
	if err != nil || !okName {
		s.replyErr(w, r, http.StatusBadRequest, "That folder name won't work.")
		return
	}
	sub, ok := s.dirRoot(w, l)
	if !ok {
		return
	}
	defer sub.Close()
	target := joinRel(rel, name)
	if err := sub.Mkdir(target, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		s.replyErr(w, r, http.StatusBadRequest, "Couldn't make that folder.")
		return
	}
	s.record(r, l, "mkdir", target, 0)
	http.Redirect(w, r, dirURL(l, target), http.StatusSeeOther)
}

const maxUnlockFails = 10

func (s *Server) shareUnlock(w http.ResponseWriter, r *http.Request) {
	l, ok := s.gate(w, r, false)
	if !ok {
		return
	}
	if l.PasswordHash == "" {
		http.Redirect(w, r, "/s/"+l.Token, http.StatusSeeOther)
		return
	}
	data := map[string]any{"Token": l.Token}
	fails, _ := s.st.RecentFailures(l.ID, s.now().Add(-15*time.Minute))
	if fails >= maxUnlockFails {
		data["Error"] = "Too many wrong tries. Wait 15 minutes and try again."
		s.render(w, http.StatusTooManyRequests, "unlock", data)
		return
	}
	if !checkPassword(l.PasswordHash, r.FormValue("password")) {
		s.record(r, l, "unlock-fail", "", 0)
		data["Error"] = "That password isn't right."
		s.render(w, http.StatusUnauthorized, "unlock", data)
		return
	}
	s.record(r, l, "unlock", "", 0)
	s.setCookie(w, unlockCookie(l), s.signedValue(s.unlockPurpose(l), unlockTTL), "/s/"+l.Token, unlockTTL)
	http.Redirect(w, r, "/s/"+l.Token, http.StatusSeeOther)
}
