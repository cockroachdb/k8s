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

//goland:noinspection SpellCheckingInspection
import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"
	certificates "k8s.io/api/certificates/v1beta1"
	core "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	types "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesCertificateManager struct {
	kubeConfig *string
	client     *kubernetes.Clientset
	logger     *log.Logger
}

//NewKubernetesCertificateManager builds a new cert manager used to interface with Kubernetes.
func NewKubernetesCertificateManager(logger *log.Logger, kubeConfig *string) (*KubernetesCertificateManager, error) {
	kcm := &KubernetesCertificateManager{logger: logger}

	var err error
	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		kcm.logger.Printf("error building kubernetes config: %s", err)
		return &KubernetesCertificateManager{}, err
	}

	kcm.client, err = kubernetes.NewForConfig(config)
	if err != nil {
		kcm.logger.Printf("error building kubernetes client: %s", err)
		return &KubernetesCertificateManager{}, err
	}

	return kcm, nil
}

// generateKubernetesCertificate will gen the CSR with the API in a way which can be auto-approved.
// ref: https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers
func (kcm *KubernetesCertificateManager) GetKubernetesCertificate(csrName string, csr []byte, wantServerAuth bool, allowPrevious bool) ([]byte, error) {

	keyUsages := []certificates.KeyUsage{
		certificates.UsageDigitalSignature,
		certificates.UsageKeyEncipherment,
		certificates.UsageClientAuth,
	}

	if wantServerAuth {
		kcm.logger.Printf("%s is a server, using server auth", csrName)
		keyUsages = append(keyUsages, certificates.UsageServerAuth)
	}

	// Build the certificate signing request.
	req := &certificates.CertificateSigningRequest{
		TypeMeta:   types.TypeMeta{Kind: "CertificateSigningRequest"},
		ObjectMeta: types.ObjectMeta{Name: csrName},
		Spec: certificates.CertificateSigningRequestSpec{
			Request: csr,
			Usages:  keyUsages,
			SignerName: func(wantServerAuth bool) *string {
				if wantServerAuth {
					signer := "kubernetes.io/legacy-unknown" // this is because the nodes need server + client.
					kcm.logger.Printf("%s is a server, using %s as the signer", csrName, signer)
					return &signer
				} else {
					signer := "kubernetes.io/kube-apiserver-client"
					kcm.logger.Printf("%s is a client, using %s as the signer", csrName, signer)
					return &signer
				}
			}(wantServerAuth),
		},
	}

	kcm.logger.Printf("csr: %#v", req)

	kcm.logger.Printf("sending create request: %s for %s\n", req.Name, *addresses)
	resp, err := kcm.client.CertificatesV1beta1().CertificateSigningRequests().Create(context.Background(), req, types.CreateOptions{})

	if err != nil && k8serrors.IsAlreadyExists(err) && allowPrevious {
		kcm.logger.Printf("attempting to use previous CSR: %s\n", req.Name)
		resp, err = kcm.client.CertificatesV1beta1().CertificateSigningRequests().Get(context.Background(), req.Name, types.GetOptions{
			TypeMeta: types.TypeMeta{
				Kind: "CertificateSigningRequest"},
		})
	}
	if err != nil {
		kcm.logger.Printf("CertificateSigningRequest.Create(%s) failed", req.Name)
		return nil, errors.Wrapf(err, "CertificateSigningRequest.Create(%s) failed", req.Name)
	}

	kcm.logger.Printf("Request sent, waiting for approval. To approve, run 'kubectl certificate approve %s'", req.Name)

	ticker := time.NewTicker(time.Second * 1)

	cert := make([]byte, 0)

Waiter:
	for {
		select {
		case <-ticker.C:

			getResp, err := kcm.client.CertificatesV1beta1().CertificateSigningRequests().Get(context.Background(), csrName, types.GetOptions{
				TypeMeta: types.TypeMeta{Kind: "CertificateSigningRequest"},
			})
			if err != nil {
				kcm.logger.Printf("error fetching %s from kubernetes api: %s", csrName, err)
				return nil, errors.Errorf("error fetching %s from kubernetes api: %s", csrName, err)
			}

			if getResp.UID != resp.UID {
				kcm.logger.Printf("got UID %v, but expected UID %s", getResp.UID, resp.UID)
			}

			// not ready, continue.
			if len(getResp.Status.Conditions) == 0 {
				kcm.logger.Printf("no conditions seen on %s, continuing", csrName)
				continue
			}

			cond := getResp.Status.Conditions[len(getResp.Status.Conditions)-1]
			if cond.Type != certificates.CertificateApproved {
				kcm.logger.Printf("csr not approved: %+v", resp.Status)
				return nil, errors.Errorf("csr not approved: %+v", resp.Status)
			}

			if getResp.Status.Certificate == nil {
				kcm.logger.Printf("csr approved, but no certificate in response. waiting some more")
				continue
			} else if getResp.Status.Certificate != nil {
				kcm.logger.Printf("certificate is provisioned")
				cert = getResp.Status.Certificate
				break Waiter
			}

			kcm.logger.Printf("request: %s, reason: %s, message: %s",
				fmt.Sprintf("request %s %s at %s", req.Name, cond.Type, cond.LastUpdateTime),
				cond.Reason,
				cond.Message)
		}
	}

	return cert, nil
}

func (kcm *KubernetesCertificateManager) StoreSecrets(secretName string, cert []byte, key []byte) error {

	secret := &core.Secret{
		ObjectMeta: types.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{"cert": cert, "key": key},
	}

	_, err := kcm.client.CoreV1().Secrets(*namespace).Create(context.Background(), secret, types.CreateOptions{})
	if err != nil {
		kcm.logger.Printf("error creating secret %s: %s", secretName, err)
	}
	return err
}

// GetSecrets attempts to lookup the certificate and key from the secrets store.
// A valid response is nil error and non-nil certificate and key.
func (kcm *KubernetesCertificateManager) GetSecrets(secretName string) ([]byte, []byte, error) {

	secret, err := kcm.client.CoreV1().Secrets(*namespace).Get(context.Background(), secretName, types.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			kcm.logger.Printf("secret %s not found", secretName)
			return nil, nil, nil
		}
		kcm.logger.Printf("error finding secret %s: %s", secretName, err)
		return nil, nil, err
	}

	if secret.Data["cert"] == nil {
		kcm.logger.Printf("secret %s is missing it's certificate")
		return nil, nil, errors.New("missing certificate")
	}

	if secret.Data["key"] == nil {
		kcm.logger.Printf("secret %s is missing it's private key")
		return nil, nil, errors.New("missing private key")
	}

	return secret.Data["cert"], secret.Data["key"], nil
}
