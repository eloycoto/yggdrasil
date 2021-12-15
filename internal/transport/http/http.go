package http

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"git.sr.ht/~spc/go-log"
	"github.com/redhatinsights/yggdrasil"
	"github.com/redhatinsights/yggdrasil/internal/clients/http"
	"github.com/redhatinsights/yggdrasil/internal/transport"
)

type Transport struct {
	ClientID        string
	HttpClient      *http.Client
	Server          string
	controlHandler  transport.CommandHandler
	dataHandler     transport.DataHandler
	pollingInterval time.Duration
	disconnected    atomic.Value
}

func NewHTTPTransport(ClientID string, server string, tlsConfig *tls.Config, userAgent string,
	pollingInterval time.Duration, controlHandler transport.CommandHandler,
	dataHandler transport.DataHandler) (*Transport, error) {
	disconnected := atomic.Value{}
	disconnected.Store(false)
	return &Transport{
		Server:          server,
		ClientID:        ClientID,
		HttpClient:      http.NewHTTPClient(tlsConfig, userAgent),
		controlHandler:  controlHandler,
		dataHandler:     dataHandler,
		pollingInterval: pollingInterval,
		disconnected:    disconnected,
	}, nil
}

func (t *Transport) Start() error {
	t.disconnected.Store(false)
	go func() {
		for {
			if t.disconnected.Load().(bool) {
				return
			}
			APIResponse, err := t.HttpClient.Get(t.getUrl("in", "control"))
			if err != nil {
				log.Tracef("Error while getting work: %v", err)
			}
			if APIResponse != nil && APIResponse.Body != nil && len(APIResponse.Body) > 0 {
				t.controlHandler(APIResponse.Body, t)
			}
			time.Sleep(t.pollingInterval)
		}
	}()

	go func() {
		for {
			if t.disconnected.Load().(bool) {
				return
			}
			APIResponse, err := t.HttpClient.Get(t.getUrl("in", "data"))
			if err != nil {
				log.Tracef("Error while getting work: %v", err)
			}
			if APIResponse != nil && APIResponse.Body != nil && len(APIResponse.Body) > 0 {
				t.dataHandler(APIResponse.Body)
			}

			time.Sleep(t.pollingInterval)
		}
	}()

	return nil
}

func (t *Transport) SendData(data yggdrasil.Data) (*yggdrasil.APIresponse, error) {
	return t.send(data, "data")
}

func (t *Transport) SendControl(ctrlMsg interface{}) (*yggdrasil.APIresponse, error) {
	return t.send(ctrlMsg, "control")
}

func (t *Transport) Disconnect(quiesce uint) {
	time.Sleep(time.Millisecond * time.Duration(quiesce))
	t.disconnected.Store(true)
}

func (t *Transport) send(message interface{}, channel string) (*yggdrasil.APIresponse, error) {
	if t.disconnected.Load().(bool) {
		return nil, nil
	}
	url := t.getUrl("out", channel)
	dataBytes, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	log.Tracef("Sending %s", string(dataBytes))
	return t.HttpClient.Post(url, headers, dataBytes)
}

func (t *Transport) getUrl(direction string, channel string) string {
	return fmt.Sprintf("http://%s/api/k4e-management/v1/%s/%s/%s", t.Server, channel, t.ClientID, direction)
}
