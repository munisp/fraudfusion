# FraudFusion Go orchestrator (journey execution engine), HTTP on :8000.
FROM golang:1.25.13-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/orchestrator ./cmd/orchestrator

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/orchestrator /orchestrator
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/orchestrator"]
