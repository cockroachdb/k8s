package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/cockroachdb/k8s/locality-checker/pkg/kubernetes"
)

const defaultLocalityMountPath = "/etc/cockroach-locality"

var prefix = flag.String("prefix", "", "prefix")

func main() {
	flag.Parse()

	ctx := context.Background()

	localityMountPath := defaultLocalityMountPath
	if flag.Arg(0) != "" {
		localityMountPath = flag.Arg(0)
	}

	log.Printf("writing locality information to %s", localityMountPath)

	nodeName := os.Getenv("KUBERNETES_NODE")
	if nodeName == "" {
		log.Fatal("KUBERNETES_NODE must be set")
	}
	clientset, err := kubernetes.BuildClientset()
	if err != nil {
		log.Fatalf("error building clientset: %v", err)
	}
	errorOnMissingLabels := os.Getenv("ERROR_ON_MISSING_LABELS")
	l := kubernetes.LocalityChecker{
		Clientset:            clientset,
		NodeName:             nodeName,
		WritePath:            localityMountPath,
		ErrorOnMissingLabels: errorOnMissingLabels == "1",
		Prefix:               *prefix,
	}
	if err := l.WriteLocality(ctx); err != nil {
		log.Fatalf("error writing locality: %v", err)
	}
}
