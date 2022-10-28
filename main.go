package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"
)

func LogInfo(f string, args ...interface{}) {
	format := fmt.Sprintf("%s\t%s\t: %s \n", time.Now().Format("2006-01-02 15:04:05"), "INFO", f)
	fmt.Printf(format, args...)
}

func main() {
	var port int

	flag.IntVar(&port, "p", 9999, "default port 9999")
	flag.Parse()

	server, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		LogInfo("Listen port %v failed, err msg: %v", port, err)
		return
	}

	LogInfo("Socks5 is running at %d....", port)

	for {
		conn, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept client failed: %v", err)
			continue
		}
		go process(conn)
	}
}

func process(conn net.Conn) {
	if err := auth(conn); err != nil {
		LogInfo("auth failed")
		_ = conn.Close()
		return
	}
	remoteAddr := conn.RemoteAddr().String()
	LogInfo("A client connect %s", remoteAddr)

	dst, err := Socks5Connect(conn)

	if err != nil {
		LogInfo("Connect error %s", err.Error())
		_ = conn.Close()
		return
	}
	Socks5Forward(conn, dst)
}

func auth(conn net.Conn) (err error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(conn, buf[:2])
	if n != 2 {
		return errors.New("Reading header:" + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("unsupported version")
	}

	n, err = io.ReadFull(conn, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods error: " + err.Error())
	}

	n, err = conn.Write([]byte{0x5, 0x0})
	if n != 2 || err != nil {
		return errors.New("resp err: " + err.Error())
	}
	return nil
}

func Socks5Connect(conn net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(conn, buf[:4])
	if n != 4 {
		return nil, errors.New("Read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := ""
	switch atyp {
	case 1:
		n, err = io.ReadFull(conn, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid ipv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3:
		n, err := io.ReadFull(conn, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname:" + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(conn, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname:" + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4:
		return nil, errors.New("IPV6 unsupported for now")
	default:
		return nil, errors.New("invalid atyp")
	}

	n, err = io.ReadFull(conn, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}

	port := binary.BigEndian.Uint16(buf[:2])

	dstAddrWithPort := fmt.Sprintf("%s:%d", addr, port)
	dst, err := net.Dial("tcp", dstAddrWithPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	n, err = conn.Write([]byte{0x5, 0x0, 0x0, 0x1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		_ = dst.Close()
		return nil, errors.New("write rsp:" + err.Error())
	}
	return dst, nil
}

func Socks5Forward(conn, target net.Conn) {
	forward := func(src, dst net.Conn) {
		defer func(src net.Conn) {
			_ = src.Close()
		}(src)
		defer func(dst net.Conn) {
			_ = dst.Close()
		}(dst)
		_, _ = io.Copy(src, dst)
	}

	go forward(conn, target)
	go forward(target, conn)
}
