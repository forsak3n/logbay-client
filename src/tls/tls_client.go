package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"
)

type Config struct {
	Host            string
	Port            int
	Cert            string
	Key             string
	CA              string
	Delimiter       byte
	ConnTimeoutSec  int
	WriteTimeoutSec int
	BufferLen       int
}

type logbayClient struct {
	host         string
	delimiter    byte
	conn         *tls.Conn
	tlsConf      *tls.Config
	connTimeout  time.Duration
	writeTimeout time.Duration
	buf          *bytes.Buffer
	mux          *sync.RWMutex
	sent         int64
}

var BufferFullErr = errors.New("buffer full")

// 4MB
const DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024

func New(conf *Config) (*logbayClient, error) {

	certificate, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)

	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()

	if len(conf.CA) > 0 {
		ca, err := ioutil.ReadFile(conf.CA)

		if err != nil {
			return nil, err
		}

		ok := roots.AppendCertsFromPEM(ca)

		if !ok {
			return nil, err
		}
	}

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		InsecureSkipVerify: true,
	}

	if conf.BufferLen == 0 {
		conf.BufferLen = DEFAULT_BUFFER_SIZE
	}

	client := &logbayClient{
		delimiter:    conf.Delimiter,
		host:         fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		tlsConf:      tlsConf,
		connTimeout:  time.Second * time.Duration(conf.ConnTimeoutSec),
		writeTimeout: time.Second * time.Duration(conf.WriteTimeoutSec),
		buf:          bytes.NewBuffer(make([]byte, 0, conf.BufferLen)),
		mux:          &sync.RWMutex{},
	}

	go func() {
		for {
			client.dial()
			client.connWrite()
		}
	}()

	return client, nil

}

func (c *logbayClient) Write(b []byte) (n int, err error) {
	return c.bufWrite(append(b, c.delimiter))
}

func (c *logbayClient) dial() {

	if c.conn != nil {
		c.conn.Close()
	}

	dialer := &net.Dialer{
		Timeout: c.connTimeout,
	}

	for {
		conn, err := tls.DialWithDialer(dialer, "tcp", c.host, c.tlsConf)

		if err == nil {
			c.conn = conn
			break
		}
	}
}

func (c *logbayClient) bufWrite(p []byte) (n int, err error) {

	c.mux.Lock()
	if c.buf.Len()+len(p) > c.buf.Cap() {
		return 0, BufferFullErr
	}

	n, err = c.buf.Write(p)
	c.mux.Unlock()

	// give some time to drain buffer
	time.Sleep(time.Millisecond)
	return
}

func (c *logbayClient) connWrite() {

main:
	for {
		c.mux.RLock()
		readBytes, err := c.buf.ReadBytes(c.delimiter)
		c.mux.RUnlock()

		if err != nil {
			continue
		}

		written := 0

		for written < len(readBytes) {

			c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
			n, err := c.conn.Write(readBytes[written:])

			written = written + n

			if err != nil {
				// better safe than sorry
				break main
			}
		}
	}
}
