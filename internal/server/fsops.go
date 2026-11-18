package server

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// All file access goes through an *os.Root, which refuses any path (or
// symlink) that resolves outside it. cleanRel is a second, stricter fence
// on top: it also refuses hidden names, so dotfiles are never listed,
// served or zipped.

var errBadPath = errors.New("bad path")

// cleanRel turns a request path into a clean slash-separated relative path.
// "" means the root. Any "..", "." or hidden segment is rejected outright
// rather than resolved.
func cleanRel(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	if strings.ContainsAny(p, "\\\x00") {
		return "", errBadPath
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, ".") {
			return "", errBadPath
		}
	}
	return p, nil
}

// osPath is what os.Root wants: "." for the root itself.
func osPath(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}

func joinRel(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "/" + b
}

type Entry struct {
	Name    string
	Rel     string // path relative to the listing's root
	IsDir   bool
	Size    int64
	ModTime time.Time
}

// list returns the visible entries of a directory, folders first.
func list(r *os.Root, rel string) ([]Entry, error) {
	f, err := r.Open(osPath(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		child := joinRel(rel, name)
		// Stat through the root so a symlink pointing outside simply
		// drops out of the listing.
		fi, err := r.Stat(child)
		if err != nil || !(fi.Mode().IsRegular() || fi.IsDir()) {
			continue
		}
		out = append(out, Entry{Name: name, Rel: child, IsDir: fi.IsDir(), Size: fi.Size(), ModTime: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// safeName makes an uploaded or typed file name safe to store: no path,
// no control characters, nothing Windows refuses, not hidden, not huge.
func safeName(n string) (string, bool) {
	n = strings.ReplaceAll(n, "\\", "/")
	n = path.Base(n)
	n = strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r):
			return -1
		case strings.ContainsRune(`/<>:"|?*`, r):
			return '_'
		}
		return r
	}, n)
	n = strings.TrimSpace(n)
	n = strings.TrimLeft(n, ". ")
	n = strings.TrimRight(n, ". ") // Windows drops trailing dots and spaces
	if n == "" {
		return "", false
	}
	const max = 200
	if len(n) > max {
		ext := path.Ext(n)
		if len(ext) > 20 {
			ext = ""
		}
		stem := n[:max-len(ext)]
		for !utf8.ValidString(stem) {
			stem = stem[:len(stem)-1]
		}
		n = stem + ext
	}
	return n, true
}

// candidate returns name, then "name (2).ext", "name (3).ext", ...
func candidate(name string, i int) string {
	if i == 1 {
		return name
	}
	ext := path.Ext(name)
	if ext == name { // ".ext"-only names can't happen after safeName, but be safe
		ext = ""
	}
	return fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), i, ext)
}

var errTooBig = errors.New("over the upload limit")

// saveNew writes src into dir under name without ever replacing an existing
// file: on a clash the new file gets a " (2)" style suffix. At most limit
// bytes are accepted. It returns the final name and the bytes written.
func saveNew(r *os.Root, dir, name string, src io.Reader, limit int64) (string, int64, error) {
	var rb [8]byte
	rand.Read(rb[:])
	tmp := joinRel(dir, ".upload-"+hex.EncodeToString(rb[:]))
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, io.LimitReader(src, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = errTooBig
	}
	if err != nil {
		r.Remove(tmp)
		return "", n, err
	}
	for i := 1; i <= 999; i++ {
		final := candidate(name, i)
		target := joinRel(dir, final)
		// A hard link fails if the target exists, so this is an atomic
		// "create only if absent" even with two uploads racing.
		lerr := r.Link(tmp, target)
		if lerr == nil {
			r.Remove(tmp)
			return final, n, nil
		}
		if errors.Is(lerr, fs.ErrExist) {
			continue
		}
		if isNoLinks(lerr) {
			// Filesystems without hard links: check, then rename. Tiny
			// race window, but it never overwrites anything that was
			// there before the check.
			if _, serr := r.Lstat(target); serr == nil {
				continue
			}
			if rerr := r.Rename(tmp, target); rerr != nil {
				r.Remove(tmp)
				return "", n, rerr
			}
			return final, n, nil
		}
		r.Remove(tmp)
		return "", n, lerr
	}
	r.Remove(tmp)
	return "", n, errors.New("too many files with that name")
}

func isNoLinks(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EMLINK)
}

// writeZip streams every visible file under rel into a zip.
func writeZip(w io.Writer, r *os.Root, rel string) error {
	zw := zip.NewWriter(w)
	fsys := r.FS()
	start := osPath(rel)
	err := fs.WalkDir(fsys, start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip what we can't read
		}
		if p != start && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		name := strings.TrimPrefix(strings.TrimPrefix(p, start), "/")
		if start == "." {
			name = p
		}
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: fi.ModTime()}
		hdr.SetMode(0o644)
		zf, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		f, err := fsys.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		_, err = io.Copy(zf, f)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}
