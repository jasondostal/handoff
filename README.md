# handoff

Send someone a link to a file or a folder. That's it.

- **File link:** they download that one file.
- **Folder link, view:** they browse the folder and download files or the whole thing as a zip.
- **Folder link, upload:** they can also add files and subfolders. They can't delete or replace
  anything; a file with a name that's already taken is saved as `name (2).ext`.

Every link has an expiry you can change at any time (1, 7, 30 or 90 days, a date, or never),
an optional password, an upload allowance for upload links, and an activity log so you can see
whether it was opened and what was downloaded or uploaded. Turn a link off and it stops working
immediately.

People you send links to don't need an account. The link is the permission.

One Go binary, SQLite, no JavaScript framework, no build step. Pages work without JavaScript;
with it you get drag and drop, an upload progress bar and copy buttons.

## Run it

```sh
docker run -d --name handoff \
  -p 8080:8080 \
  -v /srv/shared:/shares \
  -v handoff-data:/data \
  -e HANDOFF_BASE_URL=https://share.example.com \
  -e HANDOFF_ADMIN_PASSWORD_HASH='<output of: docker run --rm -it handoff hash-password>' \
  handoff
```

Then open `https://share.example.com/admin/`, find a file or folder, and press **Share…**.

Files go in the folder mounted at `/shares`, either by uploading them on the admin page or by
putting them there any other way. Links can only point inside it.

Put it behind a TLS-terminating reverse proxy. Links are bearer secrets; they must not travel
over plain HTTP.

## Configuration

| Variable | Default | |
|---|---|---|
| `HANDOFF_BASE_URL` | (required) | Public origin used to build links, e.g. `https://share.example.com` |
| `HANDOFF_ROOT` | `/shares` | The shared folder |
| `HANDOFF_DATA` | `/data` | Where `handoff.db` lives |
| `HANDOFF_LISTEN` | `:8080` | |
| `HANDOFF_ADMIN_PASSWORD_HASH` | | bcrypt hash; turns on the built-in admin sign-in. Make one with `handoff hash-password` |
| `HANDOFF_ADMIN_PASSWORD` | | Plain-text alternative to the hash, for quick tests |
| `HANDOFF_ADMIN_PROXY_SECRET` | | If your proxy already authenticates you (Authentik, Authelia, oauth2-proxy…), have it send this value in an `X-Proxy-Auth` header on `/admin` and strip that header everywhere else |
| `HANDOFF_TRUST_PROXY` | `false` | Take the client IP for the activity log from `X-Real-IP` / `X-Forwarded-For` |
| `HANDOFF_DEFAULT_UPLOAD_MB` | `1024` | Preselected allowance for new upload links |
| `HANDOFF_OWNER` | | Name shown on expired-link pages ("Ask Sam for a new one") |

At least one of the two admin options must be set.

## Security model

- **Tokens** are 128 random bits. Whoever has the link has the access, so treat links like
  passwords, and add a password to a link (sent some other way) for anything sensitive.
- **Path containment** has two layers: request paths are rejected outright if any segment is `..`,
  `.` or hidden, and all file access goes through Go's `os.Root`, which refuses anything,
  including symlinks, that resolves outside the shared folder. Dotfiles are never listed,
  served or zipped.
- **Uploaded content never runs on this origin.** Every download is
  `Content-Disposition: attachment` with `Content-Security-Policy: sandbox` and `nosniff`, and
  HTML, SVG and other active types are sent as `application/octet-stream`.
- **No overwrites, no deletes** from share links. Uploads stream straight to a temp file and are
  hard-linked into place, which fails rather than replaces if the name exists.
- **Upload allowance** per link is enforced while streaming, and claimed atomically in the
  database so parallel uploads can't overshoot it.
- **Passwords** on links are bcrypt; 10 wrong tries in 15 minutes locks the link for a while.
  Changing a link's password signs out everyone who had unlocked it.
- **CSRF**: cross-site POSTs are refused (Go's `http.CrossOriginProtection`), cookies are
  `SameSite=Strict`, `HttpOnly`, and `Secure` behind HTTPS.
- Pages send `no-store`, `noindex`, `Referrer-Policy: same-origin`, a strict CSP, and
  `frame-ancestors 'none'`.

What it doesn't do: encryption at rest (use an encrypted disk), virus scanning, resumable uploads
for multi-gigabyte files over flaky connections, or per-recipient accounts.

## Develop

```sh
./dev go test ./...      # runs the Go toolchain in Docker
docker build -t handoff .
```

## License

MIT
