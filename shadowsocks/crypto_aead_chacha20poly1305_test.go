package shadowsocks

import (
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestChaCha20Poly1305(t *testing.T) {
	serverConfig := DefaultConfig()
	serverConfig.ServerHost = "127.0.0.1"
	serverConfig.ServerPort = 7001
	serverConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	serverConfig.Method = "chacha20-ietf-poly1305"
	server, _ := NewServerContext(serverConfig)
	go server.Run()
	defer server.Wait()
	defer server.Stop()
	clientConfig := DefaultConfig()
	clientConfig.ServerHost = "127.0.0.1"
	clientConfig.ServerPort = 7001
	clientConfig.LocalPort = 6001
	clientConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	clientConfig.Method = "chacha20-ietf-poly1305"
	client, _ := NewClientContext(clientConfig)
	go client.Run()
	defer client.Wait()
	defer client.Stop()
	socks, _ := proxy.SOCKS5("tcp", "127.0.0.1:6001", nil, proxy.Direct)
	requester := &http.Client{
		Transport: &http.Transport{
			Dial: socks.Dial,
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
