package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/cockroachdb/k8s/locality-checker/pkg/kubernetes"
)

const defaultLocalityMountPath = "/etc/cockroach-locality"

var prefix = flag.String("prefix", "", "string prepended to --locality and --az flags")
var dest = flag.String("dest", defaultLocalityMountPath, "directory to which files are written")

func main() {
	flag.Parse()

	ctx := context.Background()

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
		WritePath:            *dest,
		ErrorOnMissingLabels: errorOnMissingLabels == "1",
		Prefix:               *prefix,
	}
	if err := l.WriteLocality(ctx); err != nil {
		log.Fatalf("error writing locality: %v", err)
	}
}
