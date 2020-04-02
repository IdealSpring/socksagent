package main

import (
	"ccut.cn/socksagent/core"
	"ccut.cn/socksagent/socks"
	"flag"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var config struct {
	Verbose    bool          // 详细模式
	UDPTimeout time.Duration // 纳秒
}

func main() {
	var flags struct {
		Server   string
		Client   string // 客户端连接地址或URL
		Cipher   string // 加密方式
		Password string

		Socks    string // （仅限客户端）SOCKS 侦听地址
		UDPSocks bool   // （仅限客户端）启用对SOCKS的UDP支持
		TCPTun string // （仅客户端）TCP隧道（laddr1=raddr1，laddr2=raddr2，…）
		UDPTun string // （仅客户端）UDP隧道（laddr1=raddr1，laddr2=raddr2，…）
	}

	var model string
	flag.StringVar(&model, "m", "", "server of client")
	flag.Parse()

	if model == "server" {
		// 服务端参数
		flags.Server = "ss://AEAD_CHACHA20_POLY1305:your-password@:8081"
		flags.Cipher = "AEAD_CHACHA20_POLY1305"
	} else if  model == "client" {
		// 客户端参数
		flags.Client = "ss://AEAD_CHACHA20_POLY1305:your-password@127.0.0.1:8081"
		flags.Socks = ":8088"
		flags.UDPSocks = false
		flags.TCPTun = ":8053=8.8.8.8:53,:8054=8.8.4.4:53"
		flags.UDPTun = ":8053=8.8.8.8:53,:8054=8.8.4.4:53"
	} else {
		log.Fatalln("m param is server of client")
	}

	// 详细模式
	config.Verbose = true
	// base64url编码密钥（如果为空，则从密码派生）
	var key []byte

	if flags.Server != "" {
		address := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(address, "ss://") {
			address, cipher, password, err = parseUrl(address)

			if err != nil {
				log.Fatalln(err)
			}
		}

		udpAddress := address

		// cipher: "AEAD_CHACHA20_POLY1305"
		// key   : ""
		// password: "your-password"
		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatalln(err)
		}

		go tcpRemote(address, ciph.StreamConn)
		go udpRemote(udpAddress, ciph.PacketConn)
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseUrl(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			// flags.Socks: ":8088"
			// addr: "127.0.0.1:8081"
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
			if flags.UDPSocks {
				go udpSocksLocal(flags.Socks, udpAddr, ciph.PacketConn)
			}
		}

		// ":8053=8.8.8.8:53,:8054=8.8.4.4:53"
		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(p[0], udpAddr, p[1], ciph.PacketConn)
			}
		}
	}

	// 程序接收系统 kill 命令，优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseUrl(s string) (address, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	address = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}

	return
}
