package transport

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
	"time"

	"git.sr.ht/~spc/go-log"
	"github.com/redhatinsights/yggdrasil/internal/http"
)

// HTTP is a Transporter that sends and receives data and control
// messages by sending HTTP requests to a URL.
type HTTP struct {
	clientID        string
	client          *http.Client
	server          string
	dataHandler     DataReceiveHandlerFunc
	pollingInterval time.Duration
	disconnected    atomic.Value
	userAgent       string
	isTLS           bool
}

func NewHTTPTransport(clientID string, server string, tlsConfig *tls.Config, userAgent string, pollingInterval time.Duration, dataRecvFunc DataReceiveHandlerFunc) (*HTTP, error) {
	disconnected := atomic.Value{}
	disconnected.Store(false)
	return &HTTP{
		clientID:        clientID,
		client:          http.NewHTTPClient(tlsConfig.Clone(), userAgent),
		dataHandler:     dataRecvFunc,
		pollingInterval: pollingInterval,
		disconnected:    disconnected,
		server:          server,
		userAgent:       userAgent,
		isTLS:           tlsConfig != nil,
	}, nil
}

func (t *HTTP) Reload(tlsConfig *tls.Config) error {
	*t.client = *http.NewHTTPClient(tlsConfig, t.userAgent)
	t.isTLS = tlsConfig != nil
	return nil
}

func (t *HTTP) Connect() error {
	t.disconnected.Store(false)
	go func() {
		for {
			if t.disconnected.Load().(bool) {
				return
			}
			payload, err := t.client.Get(t.getUrl("in", "control"))
			if err != nil {
				log.Tracef("cannot get HTTP request: %v", err)
			}
			if len(payload) > 0 {
				_ = t.ReceiveData(payload, "control")
			}
			time.Sleep(t.pollingInterval)
		}
	}()

	go func() {
		for {
			if t.disconnected.Load().(bool) {
				return
			}
			payload, err := t.client.Get(t.getUrl("in", "data"))
			if err != nil {
				log.Tracef("cannot get HTTP request: %v", err)
			}
			if len(payload) > 0 {
				_ = t.ReceiveData(payload, "data")
			}
			time.Sleep(t.pollingInterval)
		}
	}()

	return nil
}

func (t *HTTP) Disconnect(quiesce uint) {
	time.Sleep(time.Millisecond * time.Duration(quiesce))
	t.disconnected.Store(true)
}

func (t *HTTP) SendData(data []byte, dest string) error {
	return t.send(data, dest)
}

func (t *HTTP) ReceiveData(data []byte, dest string) error {
	t.dataHandler(data, dest)
	return nil
}

func (t *HTTP) send(message []byte, channel string) error {
	if t.disconnected.Load().(bool) {
		return nil
	}
	url := t.getUrl("out", channel)
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	log.Tracef("posting HTTP request body: %s", string(message))
	return t.client.Post(url, headers, message)
}

func (t *HTTP) getUrl(direction string, channel string) string {
	protocol := "http"
	if t.isTLS {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s/%s/%s/%s", protocol, t.server, channel, t.clientID, direction)
}
