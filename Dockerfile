FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tg-ws-proxy-go .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /out/tg-ws-proxy-go /usr/local/bin/tg-ws-proxy-go

EXPOSE 16443/tcp

ENTRYPOINT ["/usr/local/bin/tg-ws-proxy-go"]
CMD ["--host", "0.0.0.0", "--port", "16443"]
