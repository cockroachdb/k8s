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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

var (
	certificateType = flag.String("type", "", "certificate type: node or client")
	addresses       = flag.String("addresses", "", "comma-separated list of DNS names and IP addresses for node certificate")
	user            = flag.String("user", "", "username for client certificate")
	namespace       = flag.String("namespace", "", "kubernetes namespace for this pod")
	certsDir        = flag.String("certs-dir", "cockroach-certs", "certs directory")
	keySize         = flag.Int("key-size", 2048, "RSA key size in bits")
	symlinkCASource = flag.String("symlink-ca-from", "", "if non-empty, create <certs-dir>/ca.crt linking to this file")
	kubeConfig      = flag.String("kubeconfig", "", "config file if running from outside the cluster")

	kcm    = new(KubernetesCertificateManager)
	logger = new(log.Logger)
)

func main() {
	flag.Parse()

	logger = log.New(os.Stdout, "main: ", log.Ldate|log.Ltime|log.Lshortfile)

	var err error
	kcm, err = NewKubernetesCertificateManager(log.New(os.Stdout, "kcm: ", log.Ldate|log.Ltime|log.Lshortfile), kubeConfig)
	if err != nil {
		logger.Fatalf("cannot instantiate KubernetesCertificateManager: %s", err)
	}

	// Validate flags.
	if len(*namespace) == 0 {
		logger.Fatal("--namespace is required and must not be empty")
	}

	// Check certificate type.
	var template *x509.CertificateRequest
	var filename, csrName string
	var wantServerAuth bool

	hostname, err := os.Hostname()
	if err != nil || len(hostname) == 0 {
		log.Fatalf("could not determine hostname. got: %q, error: %v", hostname, err)
	}

	switch *certificateType {
	case "node":
		if len(*addresses) == 0 {
			logger.Fatal("node certificate requested, but --addresses is empty")
		}
		template = serverCSR(strings.Split(*addresses, ","))

		// Certificate name for nodes must include a node identifier. We use the hostname.
		// The CSR name is the same.
		filename = "node"
		csrName = *namespace + "." + filename + "." + strings.ToLower(hostname) // won't affect k8s, helpful for local testing
		wantServerAuth = true
	case "client":
		if len(*user) == 0 {
			logger.Fatal("client certificate requested, but --user is empty")
		}
		template = clientCSR(*user)

		// Certificate name for clients must only include the username.
		// Include the hostname in the CSR name.
		filename = "client." + *user
		csrName = *namespace + "." + filename
	default:
		logger.Fatalf("unknown certificate type requested: --type=%q. Valid types are \"node\", \"client\"", *certificateType)
	}

	logger.Printf("looking up cert and key under secret %s", csrName)
	pemCert, pemKey, err := kcm.GetSecrets(csrName)
	if err != nil {
		logger.Fatalf("failed to read from secrets: %v", err)
	}

	if pemCert == nil || pemKey == nil {
		logger.Printf("secret %s not found, sending csr", csrName)
		pemCert, pemKey, err = requestCertificate(csrName, template, wantServerAuth)
		if err != nil {
			logger.Fatalf("failed to get certificate: %v", err)
		}

		if len(pemCert) == 0 {
			logger.Fatal("missing cert from kubernetes api")
		}

		logger.Printf("storing cert and key under secret %s", csrName)
		if err := kcm.StoreSecrets(csrName, pemCert, pemKey); err != nil {
			logger.Fatalf("could not store secrets: %v", err)
		}
	}

	logger.Print("writing cert and key to local files\n")
	if err := writeFiles(filename, pemCert, pemKey); err != nil {
		logger.Fatalf("failed to write files: %v", err)
	}

	logger.Print("done.")
}

// requestCertificate builds a CSR and send its for approval.
// If approved, it will return the pem-encoded certificate and key, otherwise it returns an error.
func requestCertificate(csrName string, template *x509.CertificateRequest, wantServerAuth bool) ([]byte, []byte, error) {
	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		logger.Print(errors.Wrap(err, "error generating RSA key pair"))
		return nil, nil, errors.Wrap(err, "error generating RSA key pair")
	}

	// Convert key to PEM.
	pemKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	// Create CSR.
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		logger.Print(errors.Wrap(err, "error creating certificate request"))
		return nil, nil, errors.Wrap(err, "error creating certificate request")
	}

	// Convert CSR to PEM.
	pemCSR := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)

	// Send CSR for approval and certificate generation.
	pemCert, err := kcm.GetKubernetesCertificate(csrName, pemCSR, wantServerAuth, true)
	if err != nil {
		logger.Printf("error retrieving certificate: %s", err)
		return nil, nil, err
	}

	// now we load up the key pair to ensure they're signed correctly.
	_, err = tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		logger.Printf("error parsing keypair: %s", err)
		return nil, nil, err
	}

	return pemCert, pemKey, nil
}

// serverCSR generates a certificate signing request for a server certificate and returns it.
// Takes in the list of hosts/ip addresses this certificate applies to.
func serverCSR(hosts []string) *x509.CertificateRequest {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   "system:node:Cockroach",
		},
	}

	// Determine if addresses are IP addresses or DNS names and store them in the correct field.
	if hosts != nil {
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				csr.IPAddresses = append(csr.IPAddresses, ip)
			} else {
				csr.DNSNames = append(csr.DNSNames, h, "node") // append "node" so the servers start correctly.
			}
		}
	}

	logger.Printf("creating server csr with IP addresses %v and DNS names %v", csr.IPAddresses, csr.DNSNames)

	return csr
}

// clientCSR generates a certificate signing request for a user. Takes in the username.
func clientCSR(user string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Cockroach"},
			CommonName:   user,
		},
	}
}

func writeFiles(filePrefix string, pemCert []byte, pemKey []byte) error {
	// Make directory, but don't fail if it exists.
	if err := os.MkdirAll(*certsDir, 0755); err != nil {
		logger.Printf("could not create directory %s", *certsDir)
		return errors.Wrapf(err, "could not create directory %s", *certsDir)
	}

	// Encode and write key.
	keyPath := filepath.Join(*certsDir, filePrefix+".key")
	if err := ioutil.WriteFile(keyPath, pemKey, 0400); err != nil {
		logger.Printf("could not write private key file %s", keyPath)
		return errors.Wrapf(err, "could not write private key file %s", keyPath)
	}
	logger.Printf("wrote key file: %s", keyPath)

	// Write certificate.
	certPath := filepath.Join(*certsDir, filePrefix+".crt")
	if err := ioutil.WriteFile(certPath, pemCert, 0644); err != nil {
		logger.Printf("could not write certificate file %s", certPath)
		return errors.Wrapf(err, "could not write certificate file %s", certPath)
	}
	logger.Printf("wrote certificate file: %s", certPath)

	if len(*symlinkCASource) != 0 {
		// Symlink CA certificate. First ensure there isn't already a file at the
		// link destination because symlink is not idempotent.
		linkDest := filepath.Join(*certsDir, "ca.crt")
		if err := os.Remove(linkDest); err != nil && !os.IsNotExist(err) {
			logger.Printf("error removing previous ca.crt symlink: %v", err)
		}
		if err := os.Symlink(*symlinkCASource, linkDest); err != nil {
			logger.Printf("could not create symlink %s -> %s", linkDest, *symlinkCASource)
			return errors.Wrapf(err, "could not create symlink %s -> %s", linkDest, *symlinkCASource)
		}
		logger.Printf("symlinked CA certificate file: %s -> %s\n", linkDest, *symlinkCASource)
	}

	return nil
}
