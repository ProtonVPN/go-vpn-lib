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
	"sync"
	"syscall"
	"testing"
	"time"
)

var testKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOHlLmXMiprlnHwzI3OLGrcZVy52XITQGUq4vfGo2Yj2\n-----END PRIVATE KEY-----"
var testCert = "-----BEGIN CERTIFICATE-----\nMIIBHjCB0QIUTM7tBq1mnKSLlwuWugFy1uFiV/YwBQYDK2VwMDIxCzAJBgNVBAYT\nAkNIMQ8wDQYDVQQIDAZHZW5ldmExEjAQBgNVBAoMCXRlc3QgY2VydDAeFw0yMTA0\nMjgxNjMwMDBaFw0zMTA0MjYxNjMwMDBaMDIxCzAJBgNVBAYTAkNIMQ8wDQYDVQQI\nDAZHZW5ldmExEjAQBgNVBAoMCXRlc3QgY2VydDAqMAUGAytlcAMhAIEQpBEp1Hxl\nN7IX/oeN5oIRfNjRNtCqcRLZ0iKdfUuUMAUGAytlcANBAGjIXvothfBryJqC6X3L\nGc6wQfhBE6PxkcJLLguvNvIAK197SATYz+KJfjyOlWnuy9El0v/DBCQ3Y44oaZTN\nkQE=\n-----END CERTIFICATE-----"

type testState struct {
	mockSocket *mockMessageSocket
	mockClient mockNativeClient
}

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

type mockNativeClient struct {
	NativeClient
	testErrors []ErrorMessage
	testStates []string
	// Needed for access to testStates and testErrors.
	// NativeClient doesn't have such synchronization so adding this mutex may hide some race conditions in test.
	mu         *sync.Mutex
}

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

func createOpenMockSocket(mockSocket *mockMessageSocket) func(
	clientCert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	log func(string),
) (*MessageSocket, error) {
	return func(
		clientCert tls.Certificate,
		serverCAsPEM string,
		host string,
		certServerName string,
		log func(string),
	) (*MessageSocket, error) {
		return mockSocket.socket, nil
	}
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

func (client *mockNativeClient) Log(text string) {
	println(text)
}

func (client *mockNativeClient) OnState(state string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.testStates = append(client.testStates, state)
}

func (client *mockNativeClient) OnError(code int, description string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.testErrors = append(client.testErrors, ErrorMessage{Code: code, Description: description})
}

func (client *mockNativeClient) OnStatusUpdate(status *StatusMessage) {}
func (client *mockNativeClient) OnTlsSessionStarted()                 {}
func (client *mockNativeClient) OnTlsSessionEnded()                   {}

func createTestConnection(client *mockNativeClient, features *Features, socketFactory messageSocketFactory) *AgentConnection {
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
	mockSocket := mockMessageSocket{
		sendResults: make(chan error, 100),
		recvResults: make(chan interface{}, 100),
	}
	mockSocket.socket = newMessageSocket(
		func(socket *MessageSocket, msg string) error {
			return mockSocket.Send(msg)
		},
		func(socket *MessageSocket) (string, error) {
			return mockSocket.Receive()
		},
		func(socket *MessageSocket) error {
			return nil
		},
	)
	return &mockSocket
}

func setup() (*mockMessageSocket, *mockNativeClient) {
	mockClient := mockNativeClient{
		mu: &sync.Mutex{},
	}
	return newMockSocket(), &mockClient
}

func lastState(client *mockNativeClient) string {
	return client.testStates[len(client.testStates) - 1]
}

func TestAgentConnection_ConnectAndUnjail(t *testing.T) {
	assert := assert.New(t)
	mockSocket, mockClient := setup()

	unjaiedStatusResponse := strings.Replace(jailedStatusResponse, "jailed", "connected", -1)

	mockSocket.mockSendResults(nil)
	mockSocket.mockRecvResults(
		jailedStatusResponse,
		unjaiedStatusResponse)
	conn := createTestConnection(mockClient, nil, createOpenMockSocket(mockSocket))

	features := NewFeatures()
	features.SetBool("jail", false)
	conn.SetFeatures(features)

	// TODO: ugly
	time.Sleep(2 * time.Millisecond)

	mockClient.mu.Lock()
	defer mockClient.mu.Unlock()
	assert.Equal(0, len(mockSocket.recvResults))
	assert.Equal(0, len(mockSocket.sendResults))

	assert.Equal("Connected", lastState(mockClient))
	assert.Equal([]string{consts.StateConnecting, consts.StateSoftJailed, consts.StateConnected}, mockClient.testStates)
	assert.Equal(0, len(mockClient.testErrors))
}

func TestAgentConnection_ConnectionError(t *testing.T) {
	assert := assert.New(t)
	_, mockClient := setup()

	createTestConnection(mockClient, nil, failOpenSocket)

	time.Sleep(2 * time.Millisecond)

	mockClient.mu.Lock()
	defer mockClient.mu.Unlock()
	assert.Equal([]string{consts.StateConnecting, consts.StateServerUnreachable}, mockClient.testStates)
}

func TestAgentConnection_ReceiveError(t *testing.T) {
	assert := assert.New(t)
	mockSocket, mockClient := setup()

	mockSocket.mockSendResults(nil)
	mockSocket.mockRecvResults(&net.OpError{Err: syscall.ECONNABORTED})
	createTestConnection(mockClient, nil, createOpenMockSocket(mockSocket))

	time.Sleep(2 * time.Millisecond)

	mockClient.mu.Lock()
	defer mockClient.mu.Unlock()
	assert.Equal([]string{consts.StateConnecting, consts.StateConnectionError}, mockClient.testStates)
}
