# Single static binary with the web UI embedded.
FROM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /handoff ./cmd/handoff

FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 1000 handoff \
 && mkdir /data /shares && chown handoff:handoff /data /shares
COPY --from=build /handoff /usr/local/bin/handoff
USER handoff
ENV HANDOFF_DATA=/data HANDOFF_ROOT=/shares HANDOFF_LISTEN=:8080
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["handoff", "healthcheck"]
ENTRYPOINT ["handoff"]
