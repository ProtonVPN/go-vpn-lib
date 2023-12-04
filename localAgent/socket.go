/*
 * Copyright (c) 2021 Proton Technologies AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package localAgent

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"time"
)

type MessageSocket struct {
	send    chan string
	recv    chan string
	sendErr chan error
	recvErr chan error
	close   chan bool
	closed  bool
}

func newMessageSocket(
	send func(*MessageSocket, string) error,
	recv func(*MessageSocket) (string, error),
	closeSocket func(*MessageSocket) error,
) *MessageSocket {
	socket := new(MessageSocket)
	socket.send = make(chan string, 1)
	socket.recv = make(chan string, 1)
	socket.sendErr = make(chan error, 1)
	socket.recvErr = make(chan error, 1)
	socket.close = make(chan bool, 1)

	go func() {
		<-socket.close
		socket.closed = true
		closeSocket(socket) // #nosec G104 (ignore error)
		close(socket.send)
	}()

	go func() {
		var err error
		for msg := range socket.send {
			if err == nil {
				err = send(socket, msg)
				if err != nil {
					socket.sendErr <- err
				}
			}
		}
		close(socket.sendErr)
	}()

	go func() {
		for !socket.closed {
			msg, err := recv(socket)
			if err != nil {
				socket.recvErr <- err
				break
			} else if !socket.closed {
				socket.recv <- msg
			}
		}
		close(socket.recv)
		close(socket.recvErr)
	}()
	return socket
}

func openSocket(
	clientCert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	keepAliveSeconds int,
	keepAliveMaxCount int,
	log func(string),
) (*MessageSocket, error) {
	serverCAs := x509.NewCertPool()
	serverCAs.AppendCertsFromPEM([]byte(serverCAsPEM))

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCAs,
		ServerName:   certServerName,
		MinVersion:   tls.VersionTLS12,
	}

	keepaliveConfig := net.KeepAliveConfig{
		Enable: true,
		Idle: time.Duration(keepAliveSeconds) * time.Second,
		Interval: time.Duration(keepAliveSeconds) * time.Second,
		Count: keepAliveMaxCount,
	}
	dialer := net.Dialer{
		Timeout:         5 * time.Second,
		KeepAliveConfig: keepaliveConfig,
	}

	tlsConn, err := tls.DialWithDialer(&dialer, "tcp", host, tlsConf)
	if err == nil {
		err = tlsConn.Handshake()
		if err == nil {
			writer := bufio.NewWriter(tlsConn)
			reader := bufio.NewReader(tlsConn)

			return newMessageSocket(
				func(socket *MessageSocket, msg string) error {
					return socket.Send(writer, msg, log)
				},
				func(socket *MessageSocket) (string, error) {
					return socket.Receive(reader, log)
				},
				func(socket *MessageSocket) error {
					err := tlsConn.Close()
					if err != nil {
						log("LocalAgent error closing tls connection: " + err.Error())
					}
					return err
				},
			), nil
		}
	}
	return nil, err
}

func (socket *MessageSocket) Send(writer *bufio.Writer, msg string, log func(string)) error {
	log("LocalAgent sending: " + msg)
	msgLen := uint32(len(msg)) // #nosec G115 - it's unlikely to be negative, so the conversion is safe.

	err := binary.Write(writer, binary.BigEndian, msgLen)
	if err == nil && !socket.closed {
		err = binary.Write(writer, binary.BigEndian, []byte(msg))
		if err == nil && !socket.closed {
			err = writer.Flush()
		}
	}
	if err != nil && !socket.closed {
		log("LocalAgent send error: " + err.Error())
	}
	return err
}

func (socket *MessageSocket) Receive(reader *bufio.Reader, log func(string)) (string, error) {
	log("LocalAgent: waiting for message...")

	var msgLen uint32
	err := binary.Read(reader, binary.BigEndian, &msgLen)
	if err == nil && !socket.closed {
		msgBytes := make([]byte, msgLen)
		_, err = io.ReadFull(reader, msgBytes)
		if err == nil && !socket.closed {
			msgString := string(msgBytes)
			log("LocalAgent received: " + msgString)
			return msgString, nil
		}
	}
	if err != nil && !socket.closed {
		log("LocalAgent receive error: " + err.Error())
	}
	return "", err
}
