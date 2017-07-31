package shadowsocks

import (
	"github.com/RouterScript/ProxyClient"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

func TestChaCha20Poly1305(t *testing.T) {
	serverConfig := DefaultServerConfig()
	serverConfig.ServerHost = "127.0.0.1"
	serverConfig.ServerPort = 7001
	serverConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	serverConfig.Method = "chacha20-ietf-poly1305"
	server, _ := NewServerContext(serverConfig)
	go server.Run()
	defer server.Wait()
	defer server.Stop()
	clientConfig := DefaultClientConfig()
	clientConfig.ServerPort = 7001
	clientConfig.LocalPort = 6001
	clientConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	clientConfig.Method = "chacha20-ietf-poly1305"
	client, _ := NewClientContext(clientConfig)
	go client.Run()
	defer client.Wait()
	defer client.Stop()
	proxy, _ := url.Parse("socks5://127.0.0.1:6001")
	socks, _ := proxyclient.NewClient(proxy)
	requester := &http.Client{
		Transport: &http.Transport{
			DialContext: socks.Context,
		},
	}
	request, err := requester.Get("http://127.0.0.1:8000/hello")
	if err != nil {
		t.Fatal(err)
	}
	content, err := ioutil.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "Hello" {
		t.Fatal("Wrong content:", string(content))
	}
}
