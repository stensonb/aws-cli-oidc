package lib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Wrapper around net/url and net/http.  Fluent style modeled from Java's JAX-RS

const (
	ContentType string = "Content-Type"
)

type RestClient struct {
	httpClient *http.Client
}

type RestClientConfig struct {
	ClientCert         string
	ClientKey          string
	ClientCA           string
	InsecureSkipVerify bool
}

type WebTarget struct {
	url    url.URL
	client *RestClient
}

type Request struct {
	headers http.Header
	body    io.Reader
	url     *url.URL
	client  *RestClient
}

type Response struct {
	res *http.Response
}

func NewRestClient(config *RestClientConfig) (*RestClient, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Setup for client auth
	if config.ClientCert != "" && config.ClientKey != "" {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, err
		}

		// Load CA cert
		caCert, err := os.ReadFile(config.ClientCA)
		if err != nil {
			return nil, err
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			caCertPool = x509.NewCertPool()
		}
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.RootCAs = caCertPool
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &RestClient{
		httpClient: httpClient,
	}, nil
}

func (client *RestClient) Target(uri string) *WebTarget {
	url, err := url.Parse(uri)
	if err != nil {
		return nil
	}

	return &WebTarget{
		url:    *url,
		client: client,
	}
}

func (target *WebTarget) Url() url.URL {
	return target.url
}

func (target *WebTarget) QueryParam(name string, value string) *WebTarget {
	newTarget := &WebTarget{
		url:    target.url,
		client: target.client,
	}
	q := newTarget.url.Query()
	q.Set(name, value)
	newTarget.url.RawQuery = q.Encode()

	return newTarget
}

func (target *WebTarget) Request() *Request {
	return &Request{
		url:     &target.url,
		client:  target.client,
		headers: make(http.Header),
	}
}

func (r *Request) Form(form url.Values) *Request {
	r.headers.Set(ContentType, "application/x-www-form-urlencoded")
	r.body = strings.NewReader(form.Encode())

	return r
}

func (r *Request) Get(ctx context.Context) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url.String(), nil)
	if err != nil {
		return nil, err
	}

	request.Header = r.headers

	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	return &Response{res: res}, nil
}

func (r *Request) Post(ctx context.Context) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url.String(), r.body)
	if err != nil {
		return nil, err
	}

	request.Header = r.headers

	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	return &Response{res: res}, nil
}

func (r *Response) Status() int {
	return r.res.StatusCode
}

func (r *Response) ReadJson(data interface{}) error {
	body, err := io.ReadAll(r.res.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, data)
}

func (r *Response) MediaType() string {
	return r.res.Header.Get(ContentType)
}
