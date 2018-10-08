package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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
}

type client struct {
	host         string
	delimiter    byte
	conn         *tls.Conn
	tlsConf      *tls.Config
	connTimeout  time.Duration
	writeTimeout time.Duration
}

type LogbayClient interface {
	io.Writer
	Connect() error
}

func New(conf *Config) (LogbayClient, error) {

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

	client := &client{
		delimiter:    conf.Delimiter,
		host:         fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		tlsConf:      tlsConf,
		connTimeout:  time.Second * time.Duration(conf.ConnTimeoutSec),
		writeTimeout: time.Second * time.Duration(conf.WriteTimeoutSec),
	}

	return client, nil

}

func (c *client) Write(p []byte) (n int, err error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	return c.conn.Write(append(p, c.delimiter))
}

func (c *client) Connect() error {

	if c.conn != nil {
		c.conn.Close()
	}

	dialer := &net.Dialer{
		Timeout: c.connTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", c.host, c.tlsConf)

	if err == nil {
		c.conn = conn
	}

	return err
}
