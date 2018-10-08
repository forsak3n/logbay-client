**About**

Simple TLS client library for [Logbay](https://github.com/forsak3n/logbay).

**Install**

```bash
go get "github.com/forsak3n/logbay-client/tls"
```

**Use**

Use alias to avoid confusion with SDK's `tls` package

```go
package yourapp

import (
	client "github.com/forsak3n/logbay-client/tls"
	"net"
	"time"
)

func main() {
	
    conf := &client.Config {
        Host: "",
        Port: 9999,
        Cert: "/path/to/cert",
        Key:  "/path/to/key",
        CA:   "/path/to/CA",    // optional
        Delimiter: '\n',        // should be equal to server-side delimiter
        ConnTimeoutSec: 5,      // connection timeout in seconds
        WriteTimeoutSec: 5,     // write timeout in seconds
    }

    c, err := client.New(conf)
    
    if err != nil {
    	// probably invalid config, handle error
    }
    
    c.Connect()
    _, err = c.Write([]byte("Hello world"))
    
    if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
        // connection is dead, wait for a while and try to reconnect
        time.Sleep(5 * time.Second)
        c.Connect()
    } 
    
}
```
