FROM golang:1.24-alpine AS build
WORKDIR /src
COPY main.go ./
RUN go mod init fraudfusion.local/mobile-mock && CGO_ENABLED=0 go build -o /mobile-mock main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mobile-mock /mobile-mock
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/mobile-mock"]
