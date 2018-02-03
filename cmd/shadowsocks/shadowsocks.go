package main

import (
	"encoding/json"
	"fmt"
	s "github.com/shinku721/shadowsocks-go-ng/shadowsocks"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	serverHost    string
	serverPort    int
	portPassword  map[uint16]string
	localHost     string
	localPort     int
	password      string
	key           string
	encryptMethod string
	timeout       int
	v4only        bool
}

var (
	basename       string
	cmd            string
	pidFile        string
	configFile     string
	managerAddress string
	verbose        bool
	help           bool
	maxConn        int
	config         Config = DefaultConfig()
)

func DefaultConfig() Config {
	return Config{
		serverHost:    "0.0.0.0",
		serverPort:    8388,
		portPassword:  nil,
		localHost:     "127.0.0.1",
		localPort:     1080,
		password:      "",
		key:           "",
		encryptMethod: "chacha20-ietf-poly1305",
		timeout:       120,
		v4only:        false,
	}
}

func init() {
	basename = filepath.Base(os.Args[0])
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	flags := flag.CommandLine
	flags.StringVarP(&config.serverHost, "server_host", "s", config.serverHost, "Server host name or IP address")
	flags.IntVarP(&config.serverPort, "server_port", "p", 8388, "Server port number")
	flags.StringVarP(&config.localHost, "local_host", "b", "127.0.0.1", "Client bind host or IP")
	flags.IntVarP(&config.localPort, "local_port", "l", 1080, "Client listenning port")
	flags.StringVarP(&config.password, "password", "k", "", "Password of your server")
	flags.StringVar(&config.key, "key", "", "Key of your server, in base64")
	flags.StringVarP(&config.encryptMethod, "encrypt_method", "m", "chacha20-ietf-poly1305", "Encryption method")
	flags.IntVarP(&config.timeout, "timeout", "t", 120, "Socket timeout in seconds")
	flags.BoolVar(&config.v4only, "v4only", false, "Make server to proxy IPv4 only (server can still listen on IPv6)")
	flags.StringVarP(&pidFile, "pid_file", "f", "", "The pid file path")
	flags.StringVarP(&configFile, "config_file", "c", "", "The path to config file")
	flags.StringVar(&managerAddress, "manager_address", "", "Manager API address, either a unix socket or net address")
	flags.IntVar(&maxConn, "max-conn", 1000, "Maximum number of incoming connections (must be set due to ulimit on linux or the program will panic)")
	flags.BoolVarP(&verbose, "verbose", "v", false, "Verbose")
	flags.BoolVarP(&help, "help", "h", false, "Show this help")
	flags.SortFlags = false
	flag.Parse()
}

func PrintHelp() {
	if strings.HasSuffix(basename, "-server") || strings.HasSuffix(basename, "-local") {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	} else {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Command can be 'server' or 'local'.\n")
	}
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nSupported encryption methods:\n")
	names := make([]string, 0, len(s.Ciphers))
	for k := range s.Ciphers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(os.Stderr, "  %s\n", k)
	}
}

func ParseConfigFile(filename string) (config Config, err error) {
	config = DefaultConfig()
	var configData []byte
	configData, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	var configJson map[string]interface{}
	err = json.Unmarshal(configData, &configJson)
	if err != nil {
		return
	}
	if s, ok := configJson["server"]; ok {
		/*if config.serverHost, ok = s.([]string); !ok {
		      if serverHost, ok := s.(string); ok {
		          config.serverHost = []string{serverHost}
		      } else {
		          err = fmt.Errorf("Invalid server host in config file %s", filename)
		          return
		      }
		  }
		*/
		if config.serverHost, ok = s.(string); !ok {
			err = fmt.Errorf("Invalid server host in config file %s", filename)
			return
		}
	}
	if s, ok := configJson["server_port"]; ok {
		var p float64
		if p, ok = s.(float64); !ok || p >= 65536 || p <= 0 {
			err = fmt.Errorf("Invalid server port in config file %s", filename)
			return
		}
		config.serverPort = int(p)
	}
	if pp, ok := configJson["port_password"]; ok {
		m, ok := pp.(map[string]string)
		if !ok {
			err = fmt.Errorf("Invalid port_password in config file %s", filename)
			return
		}
		config.portPassword = make(map[uint16]string)
		for sport, pass := range m {
			var port int
			port, err = strconv.Atoi(sport)
			if err != nil {
				return
			}
			if port > 65535 || port <= 0 {
				err = fmt.Errorf("Port %d out of range in config file %s", port, filename)
				return
			}
			config.portPassword[uint16(port)] = pass
		}
	}
	if s, ok := configJson["local_address"]; ok {
		if config.localHost, ok = s.(string); !ok {
			err = fmt.Errorf("Invalid local_host in config file %s", filename)
			return
		}
	}
	if s, ok := configJson["local_port"]; ok {
		var p float64
		if p, ok = s.(float64); !ok || p >= 65536 || p <= 0 {
			err = fmt.Errorf("Invalid local_port in config file %s", filename)
			return
		}
		config.localPort = int(p)
	}
	if s, ok := configJson["password"]; ok {
		if config.password, ok = s.(string); !ok {
			err = fmt.Errorf("Invalid password in config file %s", filename)
			return
		}
	}
	if s, ok := configJson["key"]; ok {
		if config.localHost, ok = s.(string); !ok {
			err = fmt.Errorf("Invalid key in config file %s", filename)
			return
		}
	}
	if s, ok := configJson["timeout"]; ok {
		var t float64
		if t, ok = s.(float64); !ok || int(t) < 0 {
			err = fmt.Errorf("Invalid timeout in config file %s", filename)
			return
		}
		config.timeout = int(t)
	}
	if s, ok := configJson["method"]; ok {
		if config.encryptMethod, ok = s.(string); !ok {
			err = fmt.Errorf("Invalid encrypt method in config file %s", filename)
			return
		}
	}
	if s, ok := configJson["v4only"]; ok {
		config.v4only, _ = s.(bool)
	}
	return
}

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	if help {
		PrintHelp()
		return
	}
	var serverMode bool
	if strings.HasSuffix(basename, "-server") {
		serverMode = true
	} else if strings.HasSuffix(basename, "-local") {
		serverMode = false
	} else if cmd == "server" {
		serverMode = true
	} else if cmd == "local" {
		serverMode = false
	} else {
		PrintHelp()
		return
	}
	if configFile != "" {
		config, err = ParseConfigFile(configFile)
		if err != nil {
			return
		}
	}
	s.FDSetMax(maxConn)
	if serverMode { // server
		serverConfig := s.Config{
			ServerHost:    config.serverHost,
			Method:        config.encryptMethod,
			ConnectV4Only: config.v4only,
			Timeout:       time.Duration(config.timeout) * time.Second,
		}
		manager := s.NewServerManager()
		if config.portPassword != nil { // multiuser mode
			for port, password := range config.portPassword {
				serverConfig.ServerPort = uint16(port)
				serverConfig.KeyDeriver = s.NewKeyDeriver([]byte(password))
				err = manager.Add(serverConfig)
				if err != nil {
					return
				}
			}
		} else {
			serverConfig.ServerPort = uint16(config.serverPort)
			serverConfig.KeyDeriver = s.NewKeyDeriver([]byte(config.password))
			err = manager.Add(serverConfig)
			if err != nil {
				return
			}
		}
		if managerAddress != "" {
			err = manager.Listen(managerAddress)
		} else {
			for {
				time.Sleep(300 * time.Second)
			}
		}
	} else { // client
		clientConfig := s.Config{
			ServerHost: config.serverHost,
			ServerPort: uint16(config.serverPort),
			LocalHost:  config.localHost,
			LocalPort:  uint16(config.localPort),
			Method:     config.encryptMethod,
			KeyDeriver: s.NewKeyDeriver([]byte(config.password)),
			Timeout:    time.Duration(config.timeout) * time.Second,
		}
		client, err := s.NewClientContext(clientConfig)
		if err != nil {
			log.Panic(err)
		}
		go client.Run()
		log.Print(client.Wait())
	}
}
