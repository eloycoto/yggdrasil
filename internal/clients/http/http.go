package http

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"git.sr.ht/~spc/go-log"
	"github.com/redhatinsights/yggdrasil"
)

type Client struct {
	client    *http.Client
	userAgent string
}
type APIresponse struct {
	Code    int32
	Body    []byte
	URL     *url.URL
	Method  string
	Headers http.Header
}

func (resp *APIresponse) GetHeaders() map[string]string {
	res := map[string]string{}
	for k, v := range resp.Headers {
		res[k] = strings.Join(v, " ")
	}
	return res
}

// NewHTTPClient initializes the HTTP Client
func NewHTTPClient(config *tls.Config, ua string) *Client {
	client := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	client.Transport.(*http.Transport).TLSClientConfig = config

	return &Client{
		client:    client,
		userAgent: ua,
	}
}

func (c *Client) Get(url string) (*APIresponse, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %w", err)
	}
	req.Header.Add("User-Agent", c.userAgent)

	log.Debugf("sending HTTP request: %v %v", req.Method, req.URL)
	log.Tracef("request: %v", req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot download from URL: %w", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w", err)
	}
	log.Debugf("received HTTP %v: %v", resp.Status, strings.TrimSpace(string(data)))

	if resp.StatusCode >= 400 {
		return nil, &yggdrasil.APIResponseError{Code: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}

	return &APIresponse{
		Code:    int32(resp.StatusCode),
		Body:    data,
		URL:     req.URL,
		Method:  http.MethodGet,
		Headers: resp.Header,
	}, nil
}

func (c *Client) Post(url string, headers map[string]string, body []byte) (*APIresponse, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP request: %w", err)
	}

	for k, v := range headers {
		req.Header.Add(k, strings.TrimSpace(v))
	}
	req.Header.Add("User-Agent", c.userAgent)

	log.Debugf("sending HTTP request: %v %v", req.Method, req.URL)
	log.Tracef("request: %v", req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot post to URL: %w", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w", err)
	}
	log.Debugf("received HTTP %v: %v", resp.Status, strings.TrimSpace(string(data)))

	if resp.StatusCode >= 400 {
		return nil, &yggdrasil.APIResponseError{Code: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}

	return &APIresponse{
		Code:    int32(resp.StatusCode),
		Body:    data,
		URL:     req.URL,
		Method:  http.MethodGet,
		Headers: resp.Header,
	}, nil
}
