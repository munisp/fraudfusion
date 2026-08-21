FROM golang:1.24.0-alpine AS build
WORKDIR /src
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/release-gate-metrics ./main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/release-gate-metrics /release-gate-metrics
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/release-gate-metrics"]
