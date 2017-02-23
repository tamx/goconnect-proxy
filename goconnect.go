package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func auth(authenticate string, host string, username string, password string) string {
	if strings.HasPrefix(authenticate, "Basic ") {
		// not implemented
	} else if strings.HasPrefix(authenticate, "Digest ") {
		authparam := strings.Split(authenticate, ",")
		realm := ""
		nonce := ""
		for s := range authparam {
			if strings.Index(authparam[s], "Digest realm=\"") != -1 {
				realm = authparam[s]
				realm = realm[strings.Index(realm, "\"")+1:]
				realm = realm[:strings.Index(realm, "\"")]
			}
			if strings.Index(authparam[s], "nonce=\"") != -1 {
				nonce = authparam[s]
				nonce = nonce[strings.Index(nonce, "\"")+1:]
				nonce = nonce[:strings.Index(nonce, "\"")]
			}
		}
		uri := host
		method := "CONNECT"
		nc := "00000001"
		cnonce := "e79e26e0d17c978d"
		A1 := username + ":" + realm + ":" + password
		A1MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A1)))
		A2 := method + ":" + uri
		A2MD5 := fmt.Sprintf("%x", md5.Sum([]byte(A2)))
		response := A1MD5 + ":" + nonce + ":" + nc + ":" + cnonce
		response += ":auth:" + A2MD5
		responseMD5 := fmt.Sprintf("%x", md5.Sum([]byte(response)))
		resheader := "Digest username=\"" + username + "\", realm=\""
		resheader += realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri
		resheader += "\", algorithm=MD5, qop=auth, nc=" + nc
		resheader += ", cnonce=\"" + cnonce + "\", response=\""
		resheader += responseMD5 + "\""

		return resheader
	}
	return ""
}

func access(proxy string, host string, ssl bool, info string) (net.Conn, int, string) {
	log.SetFlags(log.Lshortfile)

	var conn net.Conn
	if ssl {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}

		conn2, err := tls.Dial("tcp", proxy, conf)
		if err != nil {
			log.Println(err)
			return nil, 400, ""
		}
		conn = conn2
	} else {
		conn2, err := net.Dial("tcp", proxy)
		if err != nil {
			log.Println(err)
			return nil, 400, ""
		}
		conn = conn2
	}

	n, err := conn.Write([]byte("CONNECT " + host + " HTTP/1.1\n" + info + "\n"))
	if err != nil {
		log.Println(n, err)
		return nil, 400, ""
	}

	reader := bufio.NewReaderSize(conn, 4096)
	{
		statusline, _, _ := reader.ReadLine()
		fmt.Fprintln(os.Stderr, string(statusline))
	}
	for {
		line, _, err := reader.ReadLine()
		str := string(line)
		// fmt.Fprintln(os.Stderr, str)
		if len(str) == 0 {
			break
		}
		// if resp.StatusCode == 401 {
		// authenticate := resp.Header.Get("Www-Authenticate")
		// fmt.Println("Auth: " + authenticate)
		// }
		if strings.HasPrefix(str, "Proxy-Authenticate:") {
			str = str[len("Proxy-Authenticate: "):]
			// fmt.Println(str)
			conn.Close()
			return nil, 407, str
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, 400, ""
		}
	}

	return conn, 200, ""
}

func pipe(reader io.ReadCloser, writer io.WriteCloser) {
	defer writer.Close()
	defer reader.Close()
	messageBuf := make([]byte, 1024)
	for {
		messageLen, err := reader.Read(messageBuf)
		if err != nil {
			break
		}
		writer.Write(messageBuf[:messageLen])
	}
}

func readEnv(env string, prompt string, passmask bool) string {
	str := os.Getenv(env)
	if len(str) > 0 {
		return str
	}
	fmt.Fprint(os.Stderr, prompt)
	strbyte, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	str = string(strbyte)
	return str
}

func fire(reader io.ReadCloser, writer io.WriteCloser, proxy string, host string, ssl bool, user string, password string) int {
	conn, code, authinfo := access(proxy, host, ssl, "")
	if code == 407 {
		if user == "" {
			return code
		}
		info := auth(authinfo, host, user, password)
		info = "Proxy-Authorization: " + info + "\n"
		conn, code, _ = access(proxy, host, ssl, info)
		if code == 407 {
			fmt.Fprintln(os.Stderr, "Auth Error!")
			return code
		}
	}
	// fmt.Fprintln(os.Stderr, "exec")
	defer conn.Close()
	// go io.Copy(conn, os.Stdout)
	// io.Copy(os.Stdin, conn)
	if reader != nil && writer != nil {
		go pipe(conn, writer)
		pipe(reader, conn)
	}
	return code
}

func server(port string, host string, proxy string, ssl bool, user string, password string) {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", port)
	listener, _ := net.ListenTCP("tcp", tcpAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go fire(conn, conn, proxy, host, ssl, user, password)
	}
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		state, _ := terminal.GetState(int(syscall.Stdin))
		<-c
		// sig is a ^C, handle it
		terminal.Restore(int(syscall.Stdin), state)
		os.Exit(0)
	}()

	// fmt.Fprintln(os.Stderr, "os.Args: ", os.Args)
	port := 0
	proxy := ""
	host := ""
	ssl := false

	for i := 1; i < len(os.Args); i++ {
		param := os.Args[i]
		if param == "-P" {
			port = i
			i++
			break
		} else if proxy == "" {
			proxy = param
		} else {
			host = param
		}
	}
	if port == 0 && host == "" {
		fmt.Fprintln(os.Stderr, "goconnect [proxyhost:port[/ssl]] [[-P host:port] host:port]")
		return
	}

	if strings.HasSuffix(proxy, "/ssl") {
		ssl = true
		proxy = proxy[:len(proxy)-4]
	}
	if strings.Index(proxy, ":") == -1 {
		if ssl {
			proxy += ":443"
		} else {
			proxy += ":8080"
		}
	}

	if port == 0 {
		code := fire(os.Stdin, os.Stdout, proxy, host, ssl, "", "")
		if code == 407 {
			user := readEnv("HTTP_PROXY_USER", "Username for Proxy auth: ", false)
			password := readEnv("HTTP_PROXY_PASS", "Password for "+user+": ", true)
			fire(os.Stdin, os.Stdout, proxy, host, ssl, user, password)
		}
		return
	}

	user := ""
	password := ""
	code := fire(nil, nil, proxy, host, ssl, "", "")
	if code == 407 {
		user = readEnv("HTTP_PROXY_USER", "Username for Proxy auth: ", false)
		password = readEnv("HTTP_PROXY_PASS", "Password for "+user+": ", true)
	}
	for i := port; i < len(os.Args); i++ {
		if os.Args[i] == "-P" {
			i++
			port := os.Args[i]
			i++
			host := os.Args[i]
			go server(port, host, proxy, ssl, user, password)
		} else {
			fmt.Println("Unknown option: " + os.Args[i])
		}
	}
	quit := make(chan bool)
	<-quit
}
