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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
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

	addresses = flag.String("addresses", "", "comma-separated list of DNS names and IP addresses for node certificate")
	user      = flag.String("user", "", "username for client certificate")

	namespace       = flag.String("namespace", "", "kubernetes namespace for this pod")
	certsDir        = flag.String("certs-dir", "cockroach-certs", "certs directory")
	keySize         = flag.Int("key-size", 2048, "RSA key size in bits")
	symlinkCASource = flag.String("symlink-ca-from", "", "if non-empty, create <certs-dir>/ca.crt linking to this file")
)

func main() {
	flag.Parse()
	flag.Lookup("logtostderr").Value.Set("true")

	// Validate flags.
	if len(*namespace) == 0 {
		log.Fatal("--namespace is required and must not be empty")
	}

	// Check certificate type.
	var template *x509.CertificateRequest
	var filename, csrName string
	var wantServerAuth bool

	hostname, err := os.Hostname()
	if err != nil || len(hostname) == 0 {
		log.Fatalf("could not determine hostname. got: %q, err=%v", hostname, err)
	}

	switch *certificateType {
	case "node":
		if len(*addresses) == 0 {
			log.Fatal("node certificate requested, but --addresses is empty")
		}
		template = serverCSR(strings.Split(*addresses, ","))

		// Certificate name for nodes must include a node identifier. We use the hostname.
		// The CSR name is the same.
		filename = "node"
		csrName = *namespace + "." + filename + "." + hostname
		wantServerAuth = true
	case "client":
		if len(*user) == 0 {
			log.Fatal("client certificate requested, but --user is empty")
		}
		template = clientCSR(*user)

		// Certificate name for clients must only include the username.
		// Include the hostname in the CSR name.
		filename = "client." + *user
		csrName = *namespace + "." + filename
	default:
		log.Fatalf("unknown certificate type requested: --type=%q. Valid types are \"node\", \"client\"", *certificateType)
	}

	log.Printf("Looking up cert and key under secret %s\n", csrName)
	pemCert, pemKey, err := getSecrets(csrName)
	if err != nil {
		log.Fatalf("failed to read from secrets: %v", err)
	}

	if pemCert == nil || pemKey == nil {
		log.Printf("Secret %s not found, sending CSR\n", csrName)
		pemCert, pemKey, err = requestCertificate(csrName, template, wantServerAuth)
		if err != nil {
			log.Fatalf("failed to get certificate: %v", err)
		}

		log.Printf("Storing cert and key under secret %s\n", csrName)
		if err := storeSecrets(csrName, pemCert, pemKey); err != nil {
			log.Fatalf("could not store secrets: %v", err)
		}
	}

	log.Print("Writing cert and key to local files\n")
	if err := writeFiles(filename, pemCert, pemKey); err != nil {
		log.Fatalf("failed to write files: %v", err)
	}
}

// requestCertificate builds a CSR and send its for approval.
// If approved, it will return the pem-encoded certificate and key, otherwise it returns an error.
func requestCertificate(
	csrName string, template *x509.CertificateRequest, wantServerAuth bool,
) ([]byte, []byte, error) {
	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
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
	pemCert, err := getKubernetesCertificate(csrName, pemCSR, wantServerAuth)
	if err != nil {
		return nil, nil, err
	}

	return pemCert, pemKey, nil
}

// serverCSR generates a certificate signing request for a server certificate and returns it.
// Takes in the list of hosts/ip addresses this certificate applies to.
func serverCSR(hosts []string) *x509.CertificateRequest {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Cockroach"},
			CommonName:   "node",
		},
	}

	// Determine if addresses are IP addresses or DNS names and store them in the correct field.
	if hosts != nil {
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				csr.IPAddresses = append(csr.IPAddresses, ip)
			} else {
				csr.DNSNames = append(csr.DNSNames, h)
			}
		}
	}

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
		return errors.Wrapf(err, "could not create directory %s", *certsDir)
	}

	// Encode and write key.
	keyPath := filepath.Join(*certsDir, filePrefix+".key")
	if err := ioutil.WriteFile(keyPath, pemKey, 0400); err != nil {
		return errors.Wrapf(err, "could not write private key file %s", keyPath)
	}
	fmt.Printf("wrote key file: %s\n", keyPath)

	// Write certificate.
	certPath := filepath.Join(*certsDir, filePrefix+".crt")
	if err := ioutil.WriteFile(certPath, pemCert, 0644); err != nil {
		return errors.Wrapf(err, "could not write certificate file %s", certPath)
	}
	fmt.Printf("wrote certificate file: %s\n", certPath)

	if len(*symlinkCASource) != 0 {
		// Symlink CA certificate. First ensure there isn't already a file at the
		// link destination because symlink is not idempotent.
		linkDest := filepath.Join(*certsDir, "ca.crt")
		if err := os.Remove(linkDest); err != nil && !os.IsNotExist(err) {
			log.Printf("error removing previous ca.crt symlink: %v\n", err)
		}
		if err := os.Symlink(*symlinkCASource, linkDest); err != nil {
			return errors.Wrapf(err, "could not create symlink %s -> %s", linkDest, *symlinkCASource)
		}
		fmt.Printf("symlinked CA certificate file: %s -> %s\n", linkDest, *symlinkCASource)
	}

	return nil
}
