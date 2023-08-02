FROM golang:1.20-alpine as build

RUN apk add -U --no-cache ca-certificates git bash

ENV GOPATH=""

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY pkg ./pkg
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/aws-s3-reverse-proxy -trimpath -ldflags="-s -w -extldflags '-static'"

FROM alpine:3.18

WORKDIR /proxy

RUN addgroup -S proxygroup && adduser -S proxyuser -G proxygroup

USER proxyuser

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/aws-s3-reverse-proxy /proxy

ENTRYPOINT [ "/proxy/aws-s3-reverse-proxy" ]
