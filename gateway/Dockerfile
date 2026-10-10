# Build stage. Pinned to the toolchain in .go-version so a container build and
# a local build cannot drift.
FROM golang:1.27.2-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
# CGO off keeps the binary static, so the runtime stage needs no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/server

# Runtime stage. scratch carries no shell, no package manager and no setuid
# binaries, so a container escape has nothing to work with.
FROM scratch

# A numeric user: scratch has no /etc/passwd for a name to resolve against.
USER 65532:65532

COPY --from=build /out/gateway /gateway

EXPOSE 8080
ENTRYPOINT ["/gateway"]
