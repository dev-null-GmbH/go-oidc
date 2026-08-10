//go:build ignore

// verify-conformance-client-tls proves that Go's TLS verifier accepts each
// ephemeral self-signed client leaf as an explicit trust anchor.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fatalf("usage: verify-conformance-client-tls.go <certificate-directory>")
	}
	certDir, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatalf("resolve certificate directory: %v", err)
	}

	serverCertificate := loadKeyPair(certDir, "server")
	serverRoots := loadCertPool(certDir, "server")
	clientRoots := x509.NewCertPool()
	for _, name := range []string{"client_one", "client_two"} {
		clientRoots.AddCert(loadCertificate(certDir, name))
	}

	for _, name := range []string{"client_one", "client_two"} {
		verifyHandshake(
			name,
			loadKeyPair(certDir, name),
			serverCertificate,
			serverRoots,
			clientRoots,
		)
	}
	fmt.Println("Go VerifyClientCertIfGiven accepted both ephemeral client leaves")
}

func loadCertificate(directory, name string) *x509.Certificate {
	pair := loadKeyPair(directory, name)
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		fatalf("parse %s certificate: %v", name, err)
	}
	return certificate
}

func loadCertPool(directory, name string) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(loadCertificate(directory, name))
	return pool
}

func loadKeyPair(directory, name string) tls.Certificate {
	pair, err := tls.LoadX509KeyPair(
		filepath.Join(directory, name+".crt"),
		filepath.Join(directory, name+".key"),
	)
	if err != nil {
		fatalf("load %s key pair: %v", name, err)
	}
	return pair
}

func verifyHandshake(
	expectedCommonName string,
	clientCertificate tls.Certificate,
	serverCertificate tls.Certificate,
	serverRoots *x509.CertPool,
	clientRoots *x509.CertPool,
) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	server := tls.Server(serverSide, &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
	})
	client := tls.Client(clientSide, &tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      serverRoots,
		ServerName:   "auth.localhost",
		MinVersion:   tls.VersionTLS12,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errors := make(chan error, 2)
	go func() { errors <- server.HandshakeContext(ctx) }()
	go func() { errors <- client.HandshakeContext(ctx) }()
	for range 2 {
		if err := <-errors; err != nil {
			fatalf("TLS handshake for %s: %v", expectedCommonName, err)
		}
	}

	peerCertificates := server.ConnectionState().PeerCertificates
	if len(peerCertificates) != 1 ||
		peerCertificates[0].Subject.CommonName != expectedCommonName {
		fatalf("server received the wrong client certificate for %s", expectedCommonName)
	}
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
