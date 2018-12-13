package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
)

const (
	CERT_PATH = "../../cert.pem"
	KEY_PATH  = "../../key.pem"
	HOST      = "localhost"
	PORT      = 30443
)

func getClient(host string) (*logbayClient, error) {

	conf := &Config{
		Host:            host,
		Port:            PORT,
		Cert:            CERT_PATH,
		Key:             KEY_PATH,
		Delimiter:       '\n',
		ConnTimeoutSec:  5,
		WriteTimeoutSec: 5,
	}

	return New(conf)
}

func runServer() error {

	cert, err := tls.LoadX509KeyPair(CERT_PATH, KEY_PATH)

	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, RootCAs: roots}
	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", HOST, PORT), tlsConfig)

	if err != nil {
		return err
	}

	go func() {
		conn, err := listener.Accept()
		defer conn.Close()

		if err != nil {
			return
		}

		conn.Read(make([]byte, 1024))
		listener.Close()
	}()

	return err
}

func TestNew(t *testing.T) {
	if c, err := getClient(HOST); err != nil || c == nil {
		t.Error("Failed to create logbayClient", err)
	}
}

func TestClient_Write(t *testing.T) {

	client, err := getClient(HOST)
	if err != nil {
		t.Error("Failed to create client", err)
	}

	if err := runServer(); err != nil {
		t.Error("Failed to create server", err)
	}

	if _, err = client.Write([]byte("Hello World")); err != nil {
		t.Failed()
	}
}
