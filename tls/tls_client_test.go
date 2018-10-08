package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
)

const (
	CERT_PATH = "../cert.pem"
	KEY_PATH  = "../key.pem"
	HOST      = "127.0.0.1"
	PORT      = 9999
)

func getClient() (LogbayClient, error) {

	conf := &Config{
		Host:            HOST,
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

	client, err := getClient()

	if err != nil || client == nil {
		t.Error("Failed to create client", err)
	}
}

func TestClient_Write(t *testing.T) {

	client, err := getClient()
	if err != nil {
		t.Error("Failed to create client", err)
	}

	if err := runServer(); err != nil {
		t.Error("Failed to create server", err)
	}

	if err := client.Connect(); err != nil {
		t.Error("Failed to connect", err)
	}

	_, err = client.Write([]byte("Hello World"))

	if err != nil {
		t.Failed()
	}
}
