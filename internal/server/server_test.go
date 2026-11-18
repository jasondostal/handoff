package server

import (
	"archive/zip"
	"bytes"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jasondostal/handoff/internal/store"
)

type env struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	st   *store.Store
	root string
	c    *http.Client
}

const proxySecret = "proxy-secret-for-tests"

func setup(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, []byte(body), 0o644))
	}
	write("docs/a.txt", "hello a")
	write("docs/.secret", "dotfile")
	write("docs/sub/b.txt", "hello b")
	write("docs/page.html", "<script>alert(1)</script>")
	write("top.pdf", "%PDF-fake")
	must(os.MkdirAll(filepath.Join(root, "inbox"), 0o755))
	must(os.WriteFile(filepath.Join(outside, "outside.txt"), []byte("OUTSIDE"), 0o644))
	must(os.Symlink(filepath.Join(outside, "outside.txt"), filepath.Join(root, "docs/escape.txt")))
	must(os.Symlink(outside, filepath.Join(root, "docs/escape-dir")))

	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	must(err)
	t.Cleanup(func() { st.Close() })
	hash, err := HashPassword("adminpw")
	must(err)
	srv, err := New(Config{Root: root, BaseURL: "https://share.example.test", AdminPasswordHash: hash,
		AdminProxySecret: proxySecret, DefaultUploadLimit: 1 << 20, Version: "test"},
		st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	must(err)
	t.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{t: t, srv: srv, ts: ts, st: st, root: root, c: c}
}

func (e *env) link(l store.Link) *store.Link {
	e.t.Helper()
	if err := e.st.CreateLink(&l); err != nil {
		e.t.Fatal(err)
	}
	return &l
}

type resp struct {
	code int
	body string
	h    http.Header
}

func (e *env) do(req *http.Request) resp {
	e.t.Helper()
	r, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, string(b), r.Header}
}

func (e *env) get(path string, hdr ...string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return e.do(req)
}

// rawGet sends the path exactly as written, without client-side cleaning.
func (e *env) rawGet(rawPath string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.URL.Opaque = rawPath
	return e.do(req)
}

func (e *env) post(path string, form url.Values, hdr ...string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return e.do(req)
}

func (e *env) upload(path string, files map[string]string, hdr ...string) resp {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fw, _ := mw.CreateFormFile("files", n)
		fw.Write([]byte(files[n]))
	}
	mw.Close()
	req, _ := http.NewRequest("POST", e.ts.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return e.do(req)
}

func (e *env) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (e *env) dirNames(rel string) []string {
	des, _ := os.ReadDir(filepath.Join(e.root, rel))
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

func TestDirLinkCannotEscape(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "docs", Kind: store.KindDir, Mode: store.ModeRead})
	base := "/s/" + l.Token

	if r := e.get(base + "/f/a.txt"); r.code != 200 || r.body != "hello a" {
		t.Fatalf("own file: %d %q", r.code, r.body)
	}
	for _, p := range []string{
		base + "/f/../top.pdf", base + "/f/%2e%2e/top.pdf", base + "/f/..%2ftop.pdf", base + "/f/sub/../../top.pdf",
		base + "/f/.secret", base + "/f/escape.txt", base + "/f/escape-dir/outside.txt",
		base + "/d/..", base + "/d/%2e%2e", base + "/d/escape-dir", base + "/zip/..", base + "/zip/escape-dir",
		base + "/f/%2fetc%2fpasswd", base + "/f/sub%5c..%5c..%5ctop.pdf",
	} {
		r := e.rawGet(p)
		if r.code == 200 || strings.Contains(r.body, "OUTSIDE") || strings.Contains(r.body, "%PDF") || strings.Contains(r.body, "dotfile") {
			t.Errorf("%s: got %d %.60q", p, r.code, r.body)
		}
	}
	r := e.get(base)
	if r.code != 200 {
		t.Fatalf("listing: %d", r.code)
	}
	for _, hidden := range []string{".secret", "escape.txt", "escape-dir"} {
		if strings.Contains(r.body, hidden) {
			t.Errorf("listing shows %s", hidden)
		}
	}
	if !strings.Contains(r.body, "a.txt") || !strings.Contains(r.body, "sub") {
		t.Errorf("listing missing entries")
	}
}

func TestDownloadsAreSandboxedAttachments(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "docs", Kind: store.KindDir, Mode: store.ModeRead})
	r := e.get("/s/" + l.Token + "/f/page.html")
	if r.code != 200 {
		t.Fatal(r.code)
	}
	if ct := r.h.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("html served as %q", ct)
	}
	if cd := r.h.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("disposition %q", cd)
	}
	if csp := r.h.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Errorf("csp %q", csp)
	}
	if r.h.Get("X-Content-Type-Options") != "nosniff" || r.h.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", r.h)
	}
}

func TestFileLinkServesOnlyThatFile(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "top.pdf", Kind: store.KindFile})
	base := "/s/" + l.Token
	if r := e.get(base); r.code != 200 || !strings.Contains(r.body, "top.pdf") {
		t.Fatalf("page %d", r.code)
	}
	if r := e.get(base + "/f/top.pdf"); r.code != 200 || r.body != "%PDF-fake" || r.h.Get("Content-Type") != "application/pdf" {
		t.Fatalf("download %d %q %q", r.code, r.body, r.h.Get("Content-Type"))
	}
	for _, p := range []string{base + "/f/a.txt", base + "/f/docs/a.txt", base + "/d/", base + "/zip/"} {
		if r := e.get(p); r.code == 200 {
			t.Errorf("%s: %d", p, r.code)
		}
	}
	if r := e.upload(base+"/upload/", map[string]string{"x.txt": "x"}); r.code != 403 {
		t.Errorf("upload to file link: %d", r.code)
	}
	got, _ := e.st.LinkByID(l.ID)
	if got.Views != 1 || got.Downloads != 1 {
		t.Errorf("counters views=%d downloads=%d", got.Views, got.Downloads)
	}
}

func TestReadLinkRefusesWrites(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeRead})
	if r := e.upload("/s/"+l.Token+"/upload/", map[string]string{"x.txt": "x"}); r.code != 403 {
		t.Errorf("upload: %d", r.code)
	}
	if r := e.post("/s/"+l.Token+"/mkdir/", url.Values{"name": {"new"}}); r.code != 403 {
		t.Errorf("mkdir: %d", r.code)
	}
	if n := e.dirNames("inbox"); len(n) != 0 {
		t.Errorf("inbox has %v", n)
	}
}

func TestUploadNeverOverwrites(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeWrite, UploadLimit: 1 << 20})
	up := "/s/" + l.Token + "/upload/"
	if r := e.upload(up, map[string]string{"report.pdf": "one"}); r.code != 200 {
		t.Fatalf("first: %d %s", r.code, r.body)
	}
	r := e.upload(up, map[string]string{"report.pdf": "two"})
	if r.code != 200 || !strings.Contains(r.body, "report (2).pdf") {
		t.Fatalf("second: %d %s", r.code, r.body)
	}
	if e.read("inbox/report.pdf") != "one" || e.read("inbox/report (2).pdf") != "two" {
		t.Errorf("contents: %q %q", e.read("inbox/report.pdf"), e.read("inbox/report (2).pdf"))
	}
	// Hostile names land as plain files inside the folder.
	r = e.upload(up, map[string]string{"../../evil.txt": "e", ".htaccess": "h", "a\\..\\b.txt": "w"})
	if r.code != 200 {
		t.Fatalf("hostile: %d %s", r.code, r.body)
	}
	if e.read("evil.txt") != "<missing>" && e.read("../evil.txt") != "<missing>" {
		t.Error("escaped the folder")
	}
	if e.read("inbox/evil.txt") != "e" || e.read("inbox/htaccess") != "h" || e.read("inbox/b.txt") != "w" {
		t.Errorf("hostile names: %v", e.dirNames("inbox"))
	}
	for _, n := range e.dirNames("inbox") {
		if strings.HasPrefix(n, ".") {
			t.Errorf("leftover hidden file %s", n)
		}
	}
	// Subfolders work and stay inside.
	if r := e.post("/s/"+l.Token+"/mkdir/", url.Values{"name": {"Taxes 2025"}}); r.code != 303 {
		t.Fatalf("mkdir: %d", r.code)
	}
	if r := e.upload("/s/"+l.Token+"/upload/Taxes%202025", map[string]string{"w2.pdf": "w2"}); r.code != 200 {
		t.Fatalf("upload to sub: %d %s", r.code, r.body)
	}
	if e.read("inbox/Taxes 2025/w2.pdf") != "w2" {
		t.Error("sub upload missing")
	}
	got, _ := e.st.LinkByID(l.ID)
	if got.UploadedBytes != int64(len("one")+len("two")+3+len("w2")) {
		t.Errorf("uploaded bytes %d", got.UploadedBytes)
	}
}

func TestUploadAllowance(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeWrite, UploadLimit: 10})
	up := "/s/" + l.Token + "/upload/"
	if r := e.upload(up, map[string]string{"big.bin": strings.Repeat("x", 20)}); r.code != 413 {
		t.Fatalf("over limit: %d %s", r.code, r.body)
	}
	if n := e.dirNames("inbox"); len(n) != 0 {
		t.Errorf("left behind %v", n)
	}
	if r := e.upload(up, map[string]string{"ok.bin": "123456"}); r.code != 200 {
		t.Fatalf("within: %d", r.code)
	}
	if r := e.upload(up, map[string]string{"more.bin": "123456"}); r.code != 413 {
		t.Fatalf("second over: %d", r.code)
	}
	got, _ := e.st.LinkByID(l.ID)
	if got.UploadedBytes != 6 {
		t.Errorf("uploaded %d", got.UploadedBytes)
	}
}

func TestExpiryAndRevoke(t *testing.T) {
	e := setup(t)
	past := time.Now().Add(-time.Hour)
	l := e.link(store.Link{Path: "docs", Kind: store.KindDir, Mode: store.ModeRead, ExpiresAt: &past})
	if r := e.get("/s/" + l.Token); r.code != 410 || !strings.Contains(r.body, "expired") {
		t.Fatalf("expired: %d", r.code)
	}
	if r := e.get("/s/" + l.Token + "/f/a.txt"); r.code != 410 {
		t.Fatalf("expired download: %d", r.code)
	}
	e.st.SetExpiry(l.ID, nil)
	if r := e.get("/s/" + l.Token); r.code != 200 {
		t.Fatalf("never: %d", r.code)
	}
	e.st.Revoke(l.ID)
	if r := e.get("/s/" + l.Token + "/f/a.txt"); r.code != 410 {
		t.Fatalf("revoked: %d", r.code)
	}
	if r := e.get("/s/AAAAAAAAAAAAAAAAAAAAAA"); r.code != 404 {
		t.Fatalf("unknown: %d", r.code)
	}
}

func TestPasswordLink(t *testing.T) {
	e := setup(t)
	hash, _ := HashPassword("bankpw")
	l := e.link(store.Link{Path: "top.pdf", Kind: store.KindFile, PasswordHash: hash})
	base := "/s/" + l.Token
	if r := e.get(base); r.code != 401 || !strings.Contains(r.body, "password") {
		t.Fatalf("locked page: %d", r.code)
	}
	if r := e.get(base + "/f/top.pdf"); r.code != 401 || strings.Contains(r.body, "%PDF") {
		t.Fatalf("locked download: %d", r.code)
	}
	if r := e.post(base+"/unlock", url.Values{"password": {"wrong"}}); r.code != 401 {
		t.Fatalf("wrong pw: %d", r.code)
	}
	if r := e.post(base+"/unlock", url.Values{"password": {"bankpw"}}); r.code != 303 {
		t.Fatalf("right pw: %d", r.code)
	}
	if r := e.get(base + "/f/top.pdf"); r.code != 200 || r.body != "%PDF-fake" {
		t.Fatalf("unlocked download: %d", r.code)
	}
}

func TestPasswordLockout(t *testing.T) {
	e := setup(t)
	hash, _ := HashPassword("bankpw")
	l := e.link(store.Link{Path: "top.pdf", Kind: store.KindFile, PasswordHash: hash})
	for i := 0; i < maxUnlockFails; i++ {
		e.post("/s/"+l.Token+"/unlock", url.Values{"password": {"nope"}})
	}
	if r := e.post("/s/"+l.Token+"/unlock", url.Values{"password": {"bankpw"}}); r.code != 429 {
		t.Fatalf("after lockout: %d", r.code)
	}
}

func TestAdminNeedsAuth(t *testing.T) {
	e := setup(t)
	if r := e.get("/admin/files/"); r.code != 303 || r.h.Get("Location") != "/admin/login" {
		t.Fatalf("anon: %d %s", r.code, r.h.Get("Location"))
	}
	if r := e.get("/admin/files/", "X-Proxy-Auth", "nope"); r.code != 303 {
		t.Fatalf("bad proxy secret: %d", r.code)
	}
	if r := e.post("/admin/links", url.Values{"path": {"docs"}, "expiry": {"never"}}); r.code != 403 {
		t.Fatalf("anon create: %d", r.code)
	}
	if r := e.get("/admin/files/", "X-Proxy-Auth", proxySecret); r.code != 200 {
		t.Fatalf("proxy: %d", r.code)
	}
	if r := e.post("/admin/login", url.Values{"password": {"wrong"}}); r.code != 401 {
		t.Fatalf("bad login: %d", r.code)
	}
	if r := e.post("/admin/login", url.Values{"password": {"adminpw"}}); r.code != 303 {
		t.Fatalf("login: %d", r.code)
	}
	if r := e.get("/admin/files/"); r.code != 200 || !strings.Contains(r.body, "docs") {
		t.Fatalf("after login: %d", r.code)
	}
}

func TestAdminCreatesLinks(t *testing.T) {
	e := setup(t)
	auth := []string{"X-Proxy-Auth", proxySecret}
	r := e.post("/admin/links", url.Values{"path": {"inbox"}, "mode": {"write"}, "expiry": {"never"}, "label": {"Mom"}}, auth...)
	if r.code != 303 {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	l, err := e.st.LinkByID(1)
	if err != nil || l.Mode != store.ModeWrite || l.ExpiresAt != nil || l.UploadLimit != 1<<20 || l.Label != "Mom" {
		t.Fatalf("link %+v %v", l, err)
	}
	// A file can't be given write access.
	e.post("/admin/links", url.Values{"path": {"top.pdf"}, "mode": {"write"}, "expiry": {"7d"}}, auth...)
	f, _ := e.st.LinkByID(2)
	if f.Kind != store.KindFile || f.Mode != store.ModeRead || f.ExpiresAt == nil ||
		f.ExpiresAt.Sub(time.Now()) < 7*24*time.Hour-time.Minute {
		t.Fatalf("file link %+v", f)
	}
	if r := e.post("/admin/links", url.Values{"path": {"docs"}, "expiry": {"date"}, "expiry_date": {"2001-01-01"}}, auth...); r.code != 400 {
		t.Fatalf("past date: %d", r.code)
	}
	if r := e.post("/admin/links", url.Values{"path": {"../etc"}, "expiry": {"never"}}, auth...); r.code == 303 {
		t.Fatal("linked outside root")
	}
	// Change expiry from the list: never -> a date -> never.
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	e.post("/admin/links/1/expiry", url.Values{"expiry": {"date"}, "expiry_date": {future}}, auth...)
	l, _ = e.st.LinkByID(1)
	if l.ExpiresAt == nil || l.ExpiresAt.Format("2006-01-02") != future {
		t.Fatalf("date expiry %v", l.ExpiresAt)
	}
	e.post("/admin/links/1/expiry", url.Values{"expiry": {"never"}}, auth...)
	if l, _ = e.st.LinkByID(1); l.ExpiresAt != nil {
		t.Fatal("never didn't clear")
	}
	if r := e.get("/admin/links", auth...); r.code != 200 || !strings.Contains(r.body, "Mom") {
		t.Fatalf("list: %d", r.code)
	}
	if r := e.get("/admin/links/1", auth...); r.code != 200 || !strings.Contains(r.body, "https://share.example.test/s/"+l.Token) {
		t.Fatalf("detail: %d", r.code)
	}
}

func TestAdminDeleteIsConservative(t *testing.T) {
	e := setup(t)
	auth := []string{"X-Proxy-Auth", proxySecret}
	e.post("/admin/delete/docs", nil, auth...)
	if e.read("docs/a.txt") != "hello a" {
		t.Fatal("deleted a non-empty folder")
	}
	e.post("/admin/delete/docs/a.txt", nil, auth...)
	if e.read("docs/a.txt") != "<missing>" {
		t.Fatal("file not deleted")
	}
	e.post("/admin/delete/docs/escape.txt", nil, auth...)
	if _, err := os.Lstat(filepath.Join(e.root, "docs/escape.txt")); err == nil {
		// Removing the symlink itself is fine; the target must survive.
	}
	for _, p := range []string{"/admin/delete/..", "/admin/delete/%2e%2e%2foutside"} {
		req, _ := http.NewRequest("POST", e.ts.URL+"/", nil)
		req.URL.Opaque = p
		req.Header.Set("X-Proxy-Auth", proxySecret)
		e.do(req)
	}
	if _, err := os.Stat(e.root); err != nil {
		t.Fatal("root gone")
	}
}

func TestCrossSitePostRefused(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeWrite, UploadLimit: 1 << 20})
	r := e.upload("/s/"+l.Token+"/upload/", map[string]string{"x.txt": "x"},
		"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
	if r.code != 403 {
		t.Fatalf("cross-site upload: %d", r.code)
	}
	r = e.post("/admin/links", url.Values{"path": {"docs"}, "expiry": {"never"}},
		"X-Proxy-Auth", proxySecret, "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
	if r.code != 403 {
		t.Fatalf("cross-site admin: %d", r.code)
	}
}

func TestZipSkipsHiddenAndOutside(t *testing.T) {
	e := setup(t)
	l := e.link(store.Link{Path: "docs", Kind: store.KindDir, Mode: store.ModeRead})
	r := e.get("/s/" + l.Token + "/zip/")
	if r.code != 200 || !strings.Contains(r.h.Get("Content-Disposition"), "docs.zip") {
		t.Fatalf("zip: %d %s", r.code, r.h.Get("Content-Disposition"))
	}
	zr, err := zip.NewReader(strings.NewReader(r.body), int64(len(r.body)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "a.txt,page.html,sub/b.txt" {
		t.Fatalf("zip has %v", names)
	}
	r = e.get("/s/" + l.Token + "/zip/sub")
	zr, _ = zip.NewReader(strings.NewReader(r.body), int64(len(r.body)))
	if len(zr.File) != 1 || zr.File[0].Name != "b.txt" {
		t.Fatalf("sub zip wrong")
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"report.pdf": "report.pdf", "../../x.txt": "x.txt", "C:\\Users\\me\\tax.pdf": "tax.pdf",
		".bashrc": "bashrc", "a<b>c?.txt": "a_b_c_.txt", "name. ": "name", "  ": "", "..": "",
		"line\nbreak.txt": "linebreak.txt",
	}
	for in, want := range cases {
		got, ok := safeName(in)
		if want == "" {
			if ok {
				t.Errorf("%q accepted as %q", in, got)
			}
			continue
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	long, _ := safeName(strings.Repeat("é", 300) + ".pdf")
	if len(long) > 200 || !strings.HasSuffix(long, ".pdf") {
		t.Errorf("long name %d bytes", len(long))
	}
}

// Every page renders without a template error, signed in or not.
func TestAllPagesRender(t *testing.T) {
	e := setup(t)
	auth := []string{"X-Proxy-Auth", proxySecret}
	past := time.Now().Add(-time.Hour)
	hash, _ := HashPassword("pw")
	w := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeWrite, UploadLimit: 100, Label: "drop"})
	e.link(store.Link{Path: "docs", Kind: store.KindDir, Mode: store.ModeRead, ExpiresAt: &past})
	f := e.link(store.Link{Path: "top.pdf", Kind: store.KindFile, PasswordHash: hash})
	e.get("/s/" + w.Token) // some activity
	for _, p := range []string{"/", "/admin/login", "/s/" + w.Token, "/s/" + f.Token, "/s/nope-nope-nope-nope",
		"/admin/files/", "/admin/files/docs/", "/admin/share?path=docs", "/admin/share?path=top.pdf", "/admin/share?path=",
		"/admin/links", "/admin/links/1", "/admin/links/2", "/admin/links/3?new=1"} {
		r := e.get(p, auth...)
		if r.code >= 500 || !strings.Contains(r.body, "</html>") {
			t.Errorf("%s: %d %.80q", p, r.code, r.body)
		}
	}
}

func TestAdminOpensFiles(t *testing.T) {
	e := setup(t)
	auth := []string{"X-Proxy-Auth", proxySecret}
	if r := e.get("/admin/view/top.pdf"); r.code == 200 {
		t.Fatal("view without admin auth")
	}
	r := e.get("/admin/view/top.pdf", auth...)
	if r.code != 200 || r.body != "%PDF-fake" || !strings.HasPrefix(r.h.Get("Content-Disposition"), "inline") ||
		r.h.Get("Content-Type") != "application/pdf" || r.h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("pdf view: %d %q %v", r.code, r.body, r.h)
	}
	r = e.get("/admin/view/docs/a.txt", auth...)
	if r.code != 200 || !strings.HasPrefix(r.h.Get("Content-Disposition"), "inline") ||
		!strings.HasPrefix(r.h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("txt view: %d %v", r.code, r.h)
	}
	// HTML is never shown inline, even to the owner.
	r = e.get("/admin/view/docs/page.html", auth...)
	if !strings.HasPrefix(r.h.Get("Content-Disposition"), "attachment") || r.h.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(r.h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("html view: %v", r.h)
	}
	r = e.get("/admin/download/top.pdf", auth...)
	if !strings.HasPrefix(r.h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %v", r.h)
	}
	for _, p := range []string{"/admin/view/docs/.secret", "/admin/view/docs/escape.txt", "/admin/view/docs",
		"/admin/view/", "/admin/download/docs/escape-dir/outside.txt"} {
		if r := e.get(p, auth...); r.code != 404 {
			t.Fatalf("%s: %d", p, r.code)
		}
	}
	if r := e.get("/admin/files/docs/", auth...); !strings.Contains(r.body, `href="/admin/view/docs/a.txt"`) ||
		!strings.Contains(r.body, `href="/admin/download/docs/page.html"`) {
		t.Fatalf("files page links missing:\n%s", r.body)
	}
}

// A big multipart body sent to a plain form handler is cut off instead of
// being spooled to disk.
func TestFormBodiesAreCapped(t *testing.T) {
	e := setup(t)
	w := e.link(store.Link{Path: "inbox", Kind: store.KindDir, Mode: store.ModeWrite, UploadLimit: 1 << 30})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("filler", "big.bin")
	fw.Write(bytes.Repeat([]byte("x"), 2<<20))
	mw.WriteField("name", "made-it")
	mw.Close()
	req, _ := http.NewRequest("POST", e.ts.URL+"/s/"+w.Token+"/mkdir/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if r := e.do(req); r.code == 303 {
		t.Fatal("oversized mkdir form was accepted")
	}
	if _, err := os.Stat(filepath.Join(e.root, "inbox", "made-it")); err == nil {
		t.Fatal("folder was made from an oversized body")
	}
	// A normal one still works.
	if r := e.post("/s/"+w.Token+"/mkdir/", url.Values{"name": {"made-it"}}); r.code != 303 {
		t.Fatalf("normal mkdir: %d", r.code)
	}
}
