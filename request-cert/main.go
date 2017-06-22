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
	"crypto"
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

	certsDir        = flag.String("certs-dir", "cockroach-certs", "certs directory")
	keySize         = flag.Int("key-size", 2048, "RSA key size in bits")
	symlinkCASource = flag.String("symlink-ca-from", "", "if non-empty, create <certs-dir>/ca.crt linking to this file")
)

func main() {
	flag.Parse()
	flag.Lookup("logtostderr").Value.Set("true")

	// Check certificate type.
	var template *x509.CertificateRequest
	var filePrefix string
	var wantServerAuth bool

	switch *certificateType {
	case "node":
		if len(*addresses) == 0 {
			log.Fatal("node certificate requested, but --addresses is empty")
		}
		template = serverCSR(strings.Split(*addresses, ","))
		filePrefix = "node"
		wantServerAuth = true
	case "client":
		if len(*user) == 0 {
			log.Fatal("client certificate requested, but --user is empty")
		}
		template = clientCSR(*user)
		filePrefix = "client." + *user
	default:
		log.Fatalf("unknown certificate type requested: --type=%q. Valid types are \"node\", \"client\"", *certificateType)
	}

	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("error generating RSA key pair: %v", err)
	}

	// Generate CSR. The helper splits addresses into IP or DNS names.
	pemCSR, err := templateToCSRBytes(template, privateKey)
	if err != nil {
		log.Fatalf("error generating CSR: %v", err)
	}

	// Try to build a descriptive name for the CSR, that's all the admin sees.
	csrName := filePrefix
	if hostname, err := os.Hostname(); err == nil && len(hostname) != 0 {
		csrName += "-" + hostname
	}

	pemCert, err := kubernetesSigner(csrName, pemCSR, wantServerAuth)
	if err != nil {
		log.Fatalf("CSR signing failed: %v", err)
	}

	if err := writeFiles(filePrefix, privateKey, pemCert); err != nil {
		log.Fatalf("failed to write files: %v", err)
	}
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

func templateToCSRBytes(template *x509.CertificateRequest, privateKey crypto.Signer) ([]byte, error) {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)

	return pemData, nil
}

func writeFiles(filePrefix string, privateKey *rsa.PrivateKey, pemCert []byte) error {
	// Make directory, but don't fail if it exists.
	if err := os.MkdirAll(*certsDir, 0755); err != nil {
		return errors.Wrapf(err, "could not create directory %s", *certsDir)
	}

	// Encode and write key.
	keyPath := filepath.Join(*certsDir, filePrefix+".key")
	keyContents := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	if err := ioutil.WriteFile(keyPath, keyContents, 0400); err != nil {
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
		// Symlink CA certificate.
		linkDest := filepath.Join(*certsDir, "ca.crt")
		if err := os.Symlink(*symlinkCASource, linkDest); err != nil {
			return errors.Wrapf(err, "could not create symlink %s -> %s", linkDest, *symlinkCASource)
		}
		fmt.Printf("symlinked CA certificate file: %s -> %s\n", linkDest, *symlinkCASource)
	}

	return nil
}
