FROM golang:1.17-alpine3.16 as builder

RUN apk add --no-cache ca-certificates make gcc libc-dev yarn git libc6-compat curl

WORKDIR /build

COPY . .

RUN make build

FROM alpine:3.16

COPY --from=builder /build/bin/locality-checker /bin/locality-checker

CMD /bin/locality-checker
