# chargeback-fraud-detector — fraud detector service (Keycloak fail-closed auth, Postgres, Redis).
FROM golang:1.25.13-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/chargeback-fraud-detector .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/chargeback-fraud-detector /chargeback-fraud-detector
USER nonroot:nonroot
EXPOSE 8091
ENTRYPOINT ["/chargeback-fraud-detector"]
