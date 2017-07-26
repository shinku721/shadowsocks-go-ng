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

var socks5client, socks4client, httpclient proxyclient.Dial

func TestMain(m *testing.M) {
	fmt.Println("prepare testing")
	// start http server
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})
	go func() {
		log.Fatal(http.ListenAndServe(":8000", nil))
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

	proxy, _ := url.Parse("socks5://127.0.0.1:6000")
	socks5client, _ = proxyclient.NewClient(proxy)
	proxy, _ = url.Parse("socks4a://127.0.0.1:6000")
	socks4client, _ = proxyclient.NewClient(proxy)
	proxy, _ = url.Parse("http://127.0.0.1:6000")
	httpclient, _ = proxyclient.NewClient(proxy)

	os.Exit(m.Run())
}

func TestSimpleSocks5(t *testing.T) {
	doTestSimple(t, &http.Client{
		Transport: &http.Transport{
			DialContext: socks5client.Context,
		},
	})
}

func TestSimpleSocks4a(t *testing.T) {
	doTestSimple(t, &http.Client{
		Transport: &http.Transport{
			DialContext: socks4client.Context,
		},
	})
}
/* Upstream HTTP Proxy client implementation is wrong
func TestSimpleHTTP(t *testing.T) {
	doTestSimple(t, &http.Client{
		Transport: &http.Transport{
			DialContext: httpclient.Context,
		},
	})
}
*/
func doTestSimple(t *testing.T, client *http.Client) {
	for i := 0; i < 10; i++ {
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
	for i := 0; i < 10; i++ {
		request, err := client.Get("http://[::1]:8000/hello")
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
	for i := 0; i < 10; i++ {
		request, err := client.Get("http://localhost:8000/hello")
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
}