package shadowsocks

import (
	"fmt"
	"github.com/RouterScript/ProxyClient"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// start http server
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})
	go func() {
		log.Fatal(http.ListenAndServe("127.0.0.1:8000", nil))
	}()
	fmt.Println("HTTP server is up")
	// start shadowsocks server
	serverConfig := DefaultServerConfig()
	serverConfig.ServerHost = "127.0.0.1"
	serverConfig.ServerPort = 7000
	serverConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	server, _ := NewServerContext(serverConfig)
	go server.Run()
	fmt.Println("ShadowSocks server is up")
	// start shadowsocks client
	clientConfig := DefaultClientConfig()
	clientConfig.ServerPort = 7000
	clientConfig.LocalPort = 6000
	clientConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	client, _ := NewClientContext(clientConfig)
	go client.Run()
	fmt.Println("Shadowsocks client is up")
	os.Exit(m.Run())
}

func TestSimpleSocks5(t *testing.T) {
	proxy, _ := url.Parse("socks5://127.0.0.1:6000")
	dial, _ := proxyclient.NewClient(proxy)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dial.Context,
		},
	}
	request, err := client.Get("http://127.0.0.1:8000/hello")
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
