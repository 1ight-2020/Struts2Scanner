package getClient

import (
	"Struts2Scanner/vars"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"
)

var cookieJar, _ = cookiejar.New(nil)

func GetClient() **http.Client {
	client, _ := vars.Client.Get().(*http.Client)
	transport, _ := vars.TranSport.Get().(*http.Transport)

	config, _ := vars.Tls.Get().(*tls.Config)
	config.InsecureSkipVerify = true

	transport.TLSClientConfig = config
	client.Timeout = time.Second * 5
	client.Jar = cookieJar
	client.Transport = transport

	vars.Client.Put(client)
	vars.TranSport.Put(transport)
	vars.Tls.Put(config)
	return &client
}
