# Security

handoff is a public web page that hands out files from your server, so security reports are very
welcome.

## Reporting a problem

Please report it privately through GitHub: on this repository, go to **Security → Report a
vulnerability**. Don't open a public issue for it.

Say what you found, how to reproduce it, and which version you're running (the image tag, or
the output of `handoff version`). I'll reply within a week, and once a fix is out I'm glad to
credit you in the release notes if you'd like.

## What's in scope

Anything that lets someone:

- read, list or download a file they weren't given a link to, or anything outside the shared folder
- overwrite, delete or rename existing files through a share link
- upload past a link's allowance, or keep using a link that has expired or been turned off
- get past a link's password, or into the admin pages, without the credentials
- make the browser run uploaded content on the handoff site
- crash the server or exhaust its disk or memory with modest effort

## Not a bug

- Someone who has a link can use it. Links are meant to work that way; add a password and an
  expiry for anything sensitive.
- Problems that need the admin password or the proxy secret, or shell access to the server.
- Running it over plain HTTP, or behind a proxy that doesn't strip `X-Proxy-Auth` from public
  requests as the README describes.

## Supported versions

Only the latest release gets fixes.
