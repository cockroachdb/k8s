FROM golang:1.14-alpine3.11 as builder

RUN apk add --no-cache ca-certificates make gcc libc-dev yarn git libc6-compat curl

RUN mkdir -p $GOPATH/src/github.com/cockroachdb/k8s
WORKDIR $GOPATH/src/github.com/cockroachdb/k8s

COPY . .

ENV GOPATH="/go"

RUN make build

RUN mv bin/locality-checker /bin/locality-checker

CMD /bin/locality-checker
