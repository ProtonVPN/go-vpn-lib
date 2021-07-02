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
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

var testKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOHlLmXMiprlnHwzI3OLGrcZVy52XITQGUq4vfGo2Yj2\n-----END PRIVATE KEY-----"
var testCert = "-----BEGIN CERTIFICATE-----\nMIIBHjCB0QIUTM7tBq1mnKSLlwuWugFy1uFiV/YwBQYDK2VwMDIxCzAJBgNVBAYT\nAkNIMQ8wDQYDVQQIDAZHZW5ldmExEjAQBgNVBAoMCXRlc3QgY2VydDAeFw0yMTA0\nMjgxNjMwMDBaFw0zMTA0MjYxNjMwMDBaMDIxCzAJBgNVBAYTAkNIMQ8wDQYDVQQI\nDAZHZW5ldmExEjAQBgNVBAoMCXRlc3QgY2VydDAqMAUGAytlcAMhAIEQpBEp1Hxl\nN7IX/oeN5oIRfNjRNtCqcRLZ0iKdfUuUMAUGAytlcANBAGjIXvothfBryJqC6X3L\nGc6wQfhBE6PxkcJLLguvNvIAK197SATYz+KJfjyOlWnuy9El0v/DBCQ3Y44oaZTN\nkQE=\n-----END CERTIFICATE-----"

var testLogs []string
var testErrors []ErrorMessage
var testStates []State

var jailedStatusResponse = `{
    "status": {
        "state": "jailed",
        "features": {
            "bouncing": "0",
            "randomized-nat": false,
            "split-tcp": true,
            "netshield-level": 2
        }
    }
}`

var mockSocket *mockMessageSocket
var mockClient mockNativeClient

type mockMessageSocket struct {
	socket      *MessageSocket
	sendResults chan error
	recvResults chan interface{}
}

func (socket *mockMessageSocket) Send(msg string) error {
	println("sending " + msg)
	err := <-socket.sendResults
	return err
}

func (socket *mockMessageSocket) Receive() (string, error) {
	println("receiving")
	result := <-socket.recvResults
	switch result.(type) {
	case string:
		println("received " + result.(string))
		return result.(string), nil
	default:
		println("received " + result.(error).Error())
		return "", result.(error)
	}
}

func (socket *mockMessageSocket) Close() {}

func openMockSocket(
	clientCert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	log func(string),
) (*MessageSocket, error) {
	return mockSocket.socket, nil
}

func failOpenSocket(
	clientCert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	log func(string),
) (*MessageSocket, error) {
	return nil, &net.OpError{Err: syscall.ECONNREFUSED}
}

type mockNativeClient struct {
	NativeClient
}

func (client mockNativeClient) Log(text string) {
	println(text)
	testLogs = append(testLogs, text)
}

func (client mockNativeClient) OnState(state State) {
	testStates = append(testStates, state)
}

func (client mockNativeClient) OnError(code int, description string) {
	testErrors = append(testErrors, ErrorMessage{Code: code, Description: description})
}

func (client mockNativeClient) OnStatusUpdate(status *StatusMessage) {}

func createTestConnection(client mockNativeClient, features *Features, socketFactory messageSocketFactory) *AgentConnection {
	agent, _ := newAgentConnection(testCert, testKey, "", "localhost", "localhost",
		client, features, true, socketFactory)
	return agent
}

func (socket *mockMessageSocket) mockSendResults(results ...error) {
	for _, e := range results {
		socket.sendResults <- e
	}
}

func (socket *mockMessageSocket) mockRecvResults(results ...interface{}) {
	for _, v := range results {
		socket.recvResults <- v
	}
}

func newMockSocket() *mockMessageSocket {
	return &mockMessageSocket{
		socket: newMessageSocket(
			func(socket *MessageSocket, msg string) error {
				return mockSocket.Send(msg)
			},
			func(socket *MessageSocket) (string, error) {
				return mockSocket.Receive()
			},
			func(socket *MessageSocket) error {
				return nil
			},
		),
		sendResults: make(chan error, 100),
		recvResults: make(chan interface{}, 100),
	}
}

func setup() {
	mockSocket = newMockSocket()
	testLogs = []string{}
	testErrors = []ErrorMessage{}
	testStates = []State{}
	mockClient = mockNativeClient{}
}

func TestAgentConnection_ConnectAndUnjail(t *testing.T) {
	assert := assert.New(t)
	setup()

	unjaiedStatusResponse := strings.Replace(jailedStatusResponse, "jailed", "connected", -1)

	mockSocket.mockSendResults(nil)
	mockSocket.mockRecvResults(
		jailedStatusResponse,
		unjaiedStatusResponse)
	conn := createTestConnection(mockClient, nil, openMockSocket)

	features := NewFeatures()
	features.SetBool("jail", false)
	conn.SetFeatures(features)

	// TODO: ugly
	time.Sleep(2 * time.Millisecond)

	assert.Equal(0, len(mockSocket.recvResults))
	assert.Equal(0, len(mockSocket.sendResults))

	assert.Equal("connected", conn.Status.State)
	assert.Equal([]State{consts.StateConnecting, consts.StateSoftJailed, consts.StateConnected}, testStates)
	assert.Equal(0, len(testErrors))
}

func TestAgentConnection_ConnectionError(t *testing.T) {
	assert := assert.New(t)
	setup()

	createTestConnection(mockClient, nil, failOpenSocket)

	time.Sleep(2 * time.Millisecond)

	assert.Equal([]State{consts.StateConnecting, consts.StateServerUnreachable}, testStates)
}

func TestAgentConnection_ReceiveError(t *testing.T) {
	assert := assert.New(t)
	setup()

	mockSocket.mockSendResults(nil)
	mockSocket.mockRecvResults(&net.OpError{Err: syscall.ECONNABORTED})
	createTestConnection(mockClient, nil, openMockSocket)

	time.Sleep(2 * time.Millisecond)

	assert.Equal([]State{consts.StateConnecting, consts.StateConnectionError}, testStates)
}
