FROM golang:alpine as build

RUN apk add -U --no-cache ca-certificates git bash

WORKDIR /app
COPY . .

RUN go build -o aws-s3-reverse-proxy && \
    mv ./aws-s3-reverse-proxy /go/bin

FROM alpine:3.10

WORKDIR /proxy

RUN addgroup -S proxygroup && adduser -S proxyuser -G proxygroup

USER proxyuser

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/aws-s3-reverse-proxy /proxy

ENTRYPOINT [ "/proxy/aws-s3-reverse-proxy" ]
