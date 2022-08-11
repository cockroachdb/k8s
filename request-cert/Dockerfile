FROM golang:latest as builder

WORKDIR /build
COPY . .

RUN go get -d -v
RUN go build -v -a -ldflags "-linkmode external -extldflags -static"

FROM busybox

COPY --from=builder /build/request-cert /request-cert

ENTRYPOINT ["/request-cert"]
