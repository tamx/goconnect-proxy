package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
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

func access(proxy string, host string, info string) (conn *tls.Conn, code int, authinfo string) {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", proxy, conf)
	if err != nil {
		log.Println(err)
		return
	}

	n, err := conn.Write([]byte("CONNECT " + host + " HTTP/1.1\n" + info + "\n"))
	if err != nil {
		log.Println(n, err)
		return
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
			panic(err)
		}
	}

	return conn, 200, ""
}

func pipe(reader io.Reader, writer io.Writer) {
	// defer writer.Close()
	// defer reader.Close()
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
	strbyte, _ := terminal.ReadPassword(syscall.Stdin)
	fmt.Fprintln(os.Stderr)
	str = string(strbyte)
	return str
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		state, _ := terminal.GetState(syscall.Stdin)
		<-c
		// sig is a ^C, handle it
		terminal.Restore(syscall.Stdin, state)
		os.Exit(0)
	}()

	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "goconnect [proxy host:port] [host:port]")
		return
	}

	// fmt.Fprintln(os.Stderr, "os.Args: ", os.Args)
	proxy := os.Args[1]
	host := os.Args[2]
	if strings.Index(proxy, ":") == -1 {
		proxy += ":443"
	}
	conn, code, authinfo := access(proxy, host, "")
	if code == 407 {
		user := readEnv("HTTP_PROXY_USER", "Username for Proxy auth: ", false)
		password := readEnv("HTTP_PROXY_PASS", "Password for "+user+": ", true)
		info := auth(authinfo, host, user, password)
		info = "Proxy-Authorization: " + info + "\n"
		conn, code, _ = access(proxy, host, info)
		if code == 407 {
			return
		}
	}
	// fmt.Fprintln(os.Stderr, "exec")
	defer conn.Close()
	// go io.Copy(conn, os.Stdout)
	// io.Copy(os.Stdin, conn)
	go pipe(conn, os.Stdout)
	pipe(os.Stdin, conn)
}