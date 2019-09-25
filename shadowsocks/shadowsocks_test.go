package shadowsocks

import (
	"fmt"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"testing"
)

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
	serverConfig := DefaultConfig()
	serverConfig.ServerHost = "127.0.0.1"
	serverConfig.ServerPort = 7000
	serverConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	server, _ := NewServerContext(serverConfig)
	go server.Run()
	fmt.Println("ShadowSocks server is up")

	// start shadowsocks client
	clientConfig := DefaultConfig()
	clientConfig.ServerHost = "127.0.0.1"
	clientConfig.ServerPort = 7000
	clientConfig.LocalPort = 6000
	clientConfig.KeyDeriver = NewKeyDeriver([]byte("testkey"))
	client, _ := NewClientContext(clientConfig)
	go client.Run()
	fmt.Println("Shadowsocks client is up")

	os.Exit(m.Run())
}

func TestSimpleSocks5(t *testing.T) {
	socks5client, _ := proxy.SOCKS5("tcp", "127.0.0.1:6000", nil, proxy.Direct)
	doTestSimple(t, &http.Client{
		Transport: &http.Transport{
			Dial: socks5client.Dial,
		},
	})
}

func TestSimpleHTTP(t *testing.T) {
	proxyURL, _ := url.Parse("http://127.0.0.1:6000")
	doTestSimple(t, &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	})
}

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
	if os.Getenv("NOIPV6") != "1" {
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
