// Package store keeps share links and their activity in SQLite.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Kind says what a link points at.
type Kind string

const (
	KindFile Kind = "file"
	KindDir  Kind = "dir"
)

// Mode says what a folder link allows. File links are always read.
type Mode string

const (
	ModeRead  Mode = "read"
	ModeWrite Mode = "write" // read + upload + new folder; never overwrite or delete
)

var ErrNotFound = errors.New("not found")

type Link struct {
	ID            int64
	Token         string
	Path          string // slash-separated, relative to the share root; "" is the root itself
	Kind          Kind
	Mode          Mode
	Label         string
	PasswordHash  string // bcrypt; empty means no password
	ExpiresAt     *time.Time
	UploadLimit   int64 // bytes this link may upload in total; 0 for read links
	UploadedBytes int64
	CreatedAt     time.Time
	RevokedAt     *time.Time
	LastAccessAt  *time.Time
	Views         int64
	Downloads     int64
}

// Status is why a link does or doesn't work right now.
func (l *Link) Status(now time.Time) string {
	switch {
	case l.RevokedAt != nil:
		return "revoked"
	case l.ExpiresAt != nil && !now.Before(*l.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

func (l *Link) Usable(now time.Time) bool { return l.Status(now) == "active" }

func (l *Link) CanWrite() bool { return l.Kind == KindDir && l.Mode == ModeWrite }

type Event struct {
	ID     int64
	LinkID int64
	At     time.Time
	Kind   string // view, download, zip, upload, mkdir, unlock, unlock-fail
	Path   string
	Bytes  int64
	IP     string
	UA     string
}

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS links (
	id INTEGER PRIMARY KEY,
	token TEXT NOT NULL UNIQUE,
	path TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('file','dir')),
	mode TEXT NOT NULL CHECK (mode IN ('read','write')),
	label TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL DEFAULT '',
	expires_at INTEGER,
	upload_limit INTEGER NOT NULL DEFAULT 0,
	uploaded_bytes INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	revoked_at INTEGER,
	last_access_at INTEGER,
	views INTEGER NOT NULL DEFAULT 0,
	downloads INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
	at INTEGER NOT NULL,
	kind TEXT NOT NULL,
	path TEXT NOT NULL DEFAULT '',
	bytes INTEGER NOT NULL DEFAULT 0,
	ip TEXT NOT NULL DEFAULT '',
	ua TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_link_at ON events(link_id, at DESC);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; keeps the quota check-and-add race free
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Secret returns a random 32-byte key that persists across restarts,
// used to sign session and unlock cookies.
func (s *Store) Secret() ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT v FROM settings WHERE k='secret'`).Scan(&v)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	v = make([]byte, 32)
	rand.Read(v)
	if _, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES('secret',?)`, v); err != nil {
		return nil, err
	}
	return v, nil
}

// NewToken is 128 bits from crypto/rand, URL-safe. The token is the
// capability: whoever holds it can use the link.
func NewToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func unix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0)
	return &t
}

func (s *Store) CreateLink(l *Link) error {
	if l.Token == "" {
		l.Token = NewToken()
	}
	if l.Kind == KindFile {
		l.Mode = ModeRead
	}
	if l.Mode != ModeWrite {
		l.UploadLimit = 0
	}
	l.CreatedAt = time.Now().Truncate(time.Second)
	res, err := s.db.Exec(`INSERT INTO links(token,path,kind,mode,label,password_hash,expires_at,upload_limit,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		l.Token, l.Path, l.Kind, l.Mode, l.Label, l.PasswordHash, unix(l.ExpiresAt), l.UploadLimit, l.CreatedAt.Unix())
	if err != nil {
		return err
	}
	l.ID, _ = res.LastInsertId()
	return nil
}

const linkCols = `id,token,path,kind,mode,label,password_hash,expires_at,upload_limit,uploaded_bytes,created_at,revoked_at,last_access_at,views,downloads`

func scanLink(sc interface{ Scan(...any) error }) (*Link, error) {
	var l Link
	var exp, rev, last sql.NullInt64
	var created int64
	err := sc.Scan(&l.ID, &l.Token, &l.Path, &l.Kind, &l.Mode, &l.Label, &l.PasswordHash, &exp,
		&l.UploadLimit, &l.UploadedBytes, &created, &rev, &last, &l.Views, &l.Downloads)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.ExpiresAt, l.RevokedAt, l.LastAccessAt = fromUnix(exp), fromUnix(rev), fromUnix(last)
	l.CreatedAt = time.Unix(created, 0)
	return &l, nil
}

func (s *Store) LinkByToken(token string) (*Link, error) {
	return scanLink(s.db.QueryRow(`SELECT `+linkCols+` FROM links WHERE token=?`, token))
}

func (s *Store) LinkByID(id int64) (*Link, error) {
	return scanLink(s.db.QueryRow(`SELECT `+linkCols+` FROM links WHERE id=?`, id))
}

// Links lists every link, newest first.
func (s *Store) Links() ([]*Link, error) {
	rows, err := s.db.Query(`SELECT ` + linkCols + ` FROM links ORDER BY revoked_at IS NOT NULL, created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) SetExpiry(id int64, t *time.Time) error {
	return s.exec1(`UPDATE links SET expires_at=? WHERE id=?`, unix(t), id)
}

func (s *Store) SetLabel(id int64, label string) error {
	return s.exec1(`UPDATE links SET label=? WHERE id=?`, label, id)
}

func (s *Store) Revoke(id int64) error {
	return s.exec1(`UPDATE links SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().Unix(), id)
}

func (s *Store) Delete(id int64) error {
	return s.exec1(`DELETE FROM links WHERE id=?`, id)
}

func (s *Store) exec1(q string, args ...any) error {
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReserveUpload atomically claims n bytes of a link's upload allowance.
// It returns false when the claim would go over the limit.
func (s *Store) ReserveUpload(id, n int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE links SET uploaded_bytes = uploaded_bytes + ?
		WHERE id=? AND uploaded_bytes + ? <= upload_limit`, n, id, n)
	if err != nil {
		return false, err
	}
	k, _ := res.RowsAffected()
	return k == 1, nil
}

// ReleaseUpload gives back bytes reserved for an upload that failed.
func (s *Store) ReleaseUpload(id, n int64) error {
	_, err := s.db.Exec(`UPDATE links SET uploaded_bytes = MAX(0, uploaded_bytes - ?) WHERE id=?`, n, id)
	return err
}

// Record logs an event and bumps the link's counters.
func (s *Store) Record(e Event) error {
	now := time.Now()
	if _, err := s.db.Exec(`INSERT INTO events(link_id,at,kind,path,bytes,ip,ua) VALUES(?,?,?,?,?,?,?)`,
		e.LinkID, now.Unix(), e.Kind, e.Path, e.Bytes, e.IP, truncate(e.UA, 300)); err != nil {
		return err
	}
	col := ""
	switch e.Kind {
	case "view":
		col = ", views = views + 1"
	case "download", "zip":
		col = ", downloads = downloads + 1"
	}
	_, err := s.db.Exec(`UPDATE links SET last_access_at=?`+col+` WHERE id=?`, now.Unix(), e.LinkID)
	return err
}

func (s *Store) Events(linkID int64, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT id,link_id,at,kind,path,bytes,ip,ua FROM events WHERE link_id=? ORDER BY at DESC, id DESC LIMIT ?`, linkID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at int64
		if err := rows.Scan(&e.ID, &e.LinkID, &at, &e.Kind, &e.Path, &e.Bytes, &e.IP, &e.UA); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentFailures counts unlock failures on a link since t (for lockout).
func (s *Store) RecentFailures(linkID int64, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE link_id=? AND kind='unlock-fail' AND at>=?`, linkID, since.Unix()).Scan(&n)
	return n, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
