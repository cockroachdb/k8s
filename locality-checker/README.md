# locality-checker

Locality checker is a container for detecting the region and availability zone
of a CockroachDB pod running in a public Kubernetes cloud offering.

It is meant to be run as an [init container](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/),
which writes the region and zone values of the pod to a volume mounted at
`/etc/cockroach-locality`. These values are then read by the CockroachDB pod
at startup, to fill in its [`--locality`](https://www.cockroachlabs.com/docs/stable/training/locality-and-replication-zones.html)
flag value. This allows CockroachDB to be aware of its pods' region and zone
placements within a Kubernetes deployment.

A complete locality flag which can be passed into `cockroach start` is written
to `/etc/cockroach-locality/locality`. For users that want more control of the
locality flag, the region a pod is running in is written to `/etc/cockroach-locality/region`,
and the zone is written to `/etc/cockroach-locality/zone`.

See [examples](examples/) for an example StatefulSet spec which uses the
locality-checker container to supply the `--locality` flag argument to
CockroachDB.
