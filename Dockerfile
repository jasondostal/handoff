# Single static binary with the web UI embedded.
FROM golang:1.26-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /handoff ./cmd/handoff

FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
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
