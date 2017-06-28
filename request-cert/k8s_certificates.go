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
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	types "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	core "k8s.io/client-go/pkg/api/v1"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	watchTimeout = time.Hour
)

var (
	kubeConfig  = flag.String("kubeconfig", "", "config file if running from outside the cluster")
	client      *kubernetes.Clientset
	clientError error
)

func getClient() (*kubernetes.Clientset, error) {
	if client == nil && clientError == nil {
		client, clientError = initClient()
	}
	return client, clientError
}

func initClient() (*kubernetes.Clientset, error) {
	// Create a config from the config file, or a InCluster config if empty.
	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error building kubernetes config")
	}

	// Create the client.
	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "error creating kubernetes client")
	}

	return c, err
}

func getKubernetesCertificate(csrName string, csr []byte, wantServerAuth bool) ([]byte, error) {
	client, err := getClient()
	if err != nil {
		return nil, err
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
		TypeMeta:   types.TypeMeta{Kind: "CertificateSigningRequest"},
		ObjectMeta: types.ObjectMeta{Name: csrName},
		Spec: certificates.CertificateSigningRequestSpec{
			Request: csr,
			Usages:  keyUsages,
		},
	}

	fmt.Printf("Sending create request: %s for %s\n", req.Name, *addresses)
	resp, err := client.Certificates().CertificateSigningRequests().Create(req)
	if err != nil {
		return nil, errors.Wrapf(err, "CertificateSigningRequest.Create(%s) failed", req.Name)
	}

	fmt.Printf("Request sent, waiting for approval. To approve, run 'kubectl certificate approve %s'\n", req.Name)

	// Build the watch request.
	timeout := int64(watchTimeout.Seconds())
	watchReq := types.ListOptions{
		Watch:          true,
		TimeoutSeconds: &timeout,
		FieldSelector:  fields.OneTermEqualSelector("metadata.name", csrName).String(),
	}

	resultCh, err := client.Certificates().CertificateSigningRequests().Watch(watchReq)
	if err != nil {
		return nil, errors.Wrapf(err, "CertificateSigningRequest.Watch(%s) failed: %v", csrName)
	}

	watchCh := resultCh.ResultChan()
	// Loop until we have a cert, CSR is denied, or we timed out. Bail out on errors.
	for {
		select {
		case event, ok := <-watchCh:
			if !ok {
				break
			}

			if event.Object.(*certificates.CertificateSigningRequest).UID != resp.UID {
				// Wrong object.
				fmt.Printf("received watch notification for object %v, but expected UID=%s\n", event.Object, resp.UID)
				continue
			}

			status := event.Object.(*certificates.CertificateSigningRequest).Status
			if len(status.Conditions) == 0 {
				continue
			}

			// TODO(marc): do we need to examine other conditions? For now, we only have approve and deny,
			// so the latest one should be fine.
			cond := status.Conditions[len(status.Conditions)-1]
			if cond.Type != certificates.CertificateApproved {
				return nil, errors.Errorf("CSR not approved: %+v", status)
			}

			// This seems to happen: https://github.com/kubernetes/kubernetes/issues/47911
			if status.Certificate == nil {
				fmt.Printf("CSR approved, but no certificate in response. Waiting some more\n")
				continue
			}

			fmt.Printf("request %s %s at %s\n", req.Name, cond.Type, cond.LastUpdateTime)
			fmt.Printf("  reason:   %s\n", cond.Reason)
			fmt.Printf("  message:  %s\n", cond.Message)
			return status.Certificate, nil
		case <-time.After(time.Second * 30):
			// Print a "still waiting" message every 30s.
			fmt.Printf("%s: waiting for 'kubectl certificate approve %s'\n", time.Now(), req.Name)
			continue
		}
	}

	return nil, errors.New("watch channel closed")
}

func storeSecrets(secretName string, cert []byte, key []byte) error {
	client, err := getClient()
	if err != nil {
		return err
	}

	secret := &core.Secret{
		ObjectMeta: types.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{"cert": cert, "key": key},
	}

	_, err = client.Secrets(*namespace).Create(secret)
	return err
}

// getSecrets attempts to lookup the certificate and key from the secrets store.
// A valid response is nil error and non-nil certificate and key.
func getSecrets(secretName string) ([]byte, []byte, error) {
	client, err := getClient()
	if err != nil {
		return nil, nil, err
	}

	secret, err := client.Core().Secrets(*namespace).Get(secretName, types.GetOptions{})
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	// We let missing fields return nil.
	return secret.Data["cert"], secret.Data["key"], nil
}
