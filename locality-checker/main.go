package main

import (
	"context"
	"log"
	"os"

	"github.com/cockroachdb/k8s/locality-checker/pkg/kubernetes"
)

const defaultLocalityMountPath = "/etc/cockroach-locality"

func main() {
	ctx := context.Background()
	var localityMountPath string
	if len(os.Args) == 2 {
		localityMountPath = os.Args[1]
	} else {
		localityMountPath = defaultLocalityMountPath
	}
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
	}
	if err := l.WriteLocality(ctx); err != nil {
		log.Fatalf("error writing locality: %v", err)
	}
}
