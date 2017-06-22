# Overview

The Dockerfile in this directory contains the "request-certs" binary which
sends a certificate signing request (CSR) to kubernetes and waits for
the signed certificate to be approved.

It can be used to request cockroach "node" or "client" certificates, storing them
using the cockroach naming scheme. It can optionally symlink the kubernetes CA certificate.
See the [cockroach kubernetes configs](https://github.com/cockroachdb/cockroach/tree/master/cloud/kubernetes) for examples.

# Pushing a new version

Assuming you're logged in to a Docker Hub account that can push to the
cockroachdb organization, [check the latest tag of the
cockroachdb/cockroach-k8s-request-cert
container](https://hub.docker.com/r/cockroachdb/cockroach-k8s-request-cert/tags/) so
that you know what tag number to use next, then cd to this directory and run:

```shell
# Get the dependencies.
$ go get ./...

# Build a static linux binary.
$ CGO_ENABLED=0 GOOS=linux go build -a .

# Optionally strip the binary.
$ strip -S request-cert

NEW_TAG=0.0 # replace 0.0 with the next appropriate tag number

# Build the docker image.
$ docker build -t "cockroachdb/cockroach-k8s-request-cert:${NEW_TAG}" .

# Push the docker image.
docker push "cockroachdb/cockroach-k8s-request-cert:${NEW_TAG}"
```
