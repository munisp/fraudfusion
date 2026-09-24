# temporal-orchestrator — Temporal worker executing journey workflows.
# Pure worker (no HTTP listener); alpine base so compose/k8s can run a
# process-liveness healthcheck (kill -0 1).
FROM golang:1.25.13-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/temporal-orchestrator .

FROM alpine:3.21

RUN addgroup -S app && adduser -S -G app app
COPY --from=build /out/temporal-orchestrator /usr/local/bin/temporal-orchestrator
USER app:app
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD kill -0 1 || exit 1
ENTRYPOINT ["temporal-orchestrator"]
