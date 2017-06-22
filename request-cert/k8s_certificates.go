// Copyright 2017 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// Author: Marc berhault (marc@cockroachlabs.com)

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/pkg/errors"

	types "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeConfig = flag.String("kubeconfig", "", "config file if running from outside the cluster")
)

func kubernetesSigner(csrName string, csr []byte, wantServerAuth bool) ([]byte, error) {
	// Create a config from the config file, or a InCluster config if empty.
	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error building kubernetes config")
	}

	// Create the client.
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "error creating kubernetes client")
	}

	keyUsages := []certificates.KeyUsage{
		certificates.UsageDigitalSignature,
		certificates.UsageKeyEncipherment,
		certificates.UsageClientAuth,
	}
	if wantServerAuth {
		keyUsages = append(keyUsages, certificates.UsageServerAuth)
	}

	// Build the certificate signing request.
	req := &certificates.CertificateSigningRequest{
		ObjectMeta: types.ObjectMeta{
			Name: csrName,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups:  []string{"system:authenticated"},
			Request: csr,
			Usages:  keyUsages,
		},
	}

	fmt.Printf("Sending create request: %s for %s\n", req.Name, *addresses)
	resp, err := client.Certificates().CertificateSigningRequests().Create(req)
	if err != nil {
		return nil, errors.Wrapf(err, "CertificateSigningRequest.Create(%s) failed", req.Name)
	}

	fmt.Printf("Request sent. To approve, run 'kubectl certificate approve %s'\n", req.Name)

	// TODO(mberhault): we may want a timeout here, perhaps also retries.
	lastLog := time.Now()
	for {
		resp, err = client.Certificates().CertificateSigningRequests().Get(req.Name, types.GetOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "CertificateSigningRequest.Get(%s) failed", req.Name)
		}

		// Empty conditions means pending.
		if len(resp.Status.Conditions) != 0 {
			break
		}

		if time.Since(lastLog) > time.Second*30 {
			now := time.Now()
			fmt.Printf("%s: waiting for 'kubectl certificate approve %s'\n", now, req.Name)
			lastLog = now
		}

		time.Sleep(time.Second * 5)
	}

	status := resp.Status.Conditions[0]
	fmt.Printf("request %s %s at %s\n", req.Name, status.Type, status.LastUpdateTime)
	fmt.Printf("  reason:   %s\n", status.Reason)
	fmt.Printf("  message:  %s\n", status.Message)

	if status.Type != certificates.CertificateApproved {
		return nil, errors.Errorf("certificate not approved: %+v", status)
	}

	return resp.Status.Certificate, nil
}
