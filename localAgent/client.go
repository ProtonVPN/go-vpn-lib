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
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

type State = string
type ErrorCode = int

type Consts struct {
	// States
	StateConnecting             State
	StateConnected              State
	StateSoftJailed             State
	StateHardJailed             State
	StateConnectionError        State
	StateServerUnreachable      State
	StateServerCertificateError State
	StateClientCertificateError State
	StateDisconnected           State

	// Error codes
	ErrorCodeGuestSession              ErrorCode
	ErrorCodeRestrictedServer          ErrorCode
	ErrorCodeBadCertSignature          ErrorCode
	ErrorCodeCertNotProvided           ErrorCode
	ErrorCodeCertificateExpired        ErrorCode
	ErrorCodeCertificateRevoked        ErrorCode
	ErrorCodeMaxSessionsUnknown        ErrorCode
	ErrorCodeMaxSessionsFree           ErrorCode
	ErrorCodeMaxSessionsBasic          ErrorCode
	ErrorCodeMaxSessionsPlus           ErrorCode
	ErrorCodeMaxSessionsVisionary      ErrorCode
	ErrorCodeMaxSessionsPro            ErrorCode
	ErrorCodeKeyUsedMultipleTimes      ErrorCode
	ErrorCodeServerError               ErrorCode
	ErrorCodePolicyViolationLowPlan    ErrorCode
	ErrorCodePolicyViolationDelinquent ErrorCode
	ErrorCodeUserTorrentNotAllowed     ErrorCode
	ErrorCodeUserBadBehavior           ErrorCode

	// NOTE: initialize in var consts when adding new
}

var consts = &Consts{
	StateConnecting:             "Connecting",
	StateConnected:              "Connected",
	StateSoftJailed:             "SoftJailed",
	StateHardJailed:             "HardJailed",
	StateConnectionError:        "ConnectionError",
	StateServerUnreachable:      "ServerUnreachable",
	StateServerCertificateError: "ServerCertificateError",
	StateClientCertificateError: "ClientCertificateError",
	StateDisconnected:           "Disconnected",

	ErrorCodeGuestSession:              86100,
	ErrorCodeRestrictedServer:          86104,
	ErrorCodeBadCertSignature:          86105,
	ErrorCodeCertNotProvided:           86106,
	ErrorCodeCertificateExpired:        86101,
	ErrorCodeCertificateRevoked:        86102,
	ErrorCodeMaxSessionsUnknown:        86110,
	ErrorCodeMaxSessionsFree:           86111,
	ErrorCodeMaxSessionsBasic:          86112,
	ErrorCodeMaxSessionsPlus:           86113,
	ErrorCodeMaxSessionsVisionary:      86114,
	ErrorCodeMaxSessionsPro:            86115,
	ErrorCodeKeyUsedMultipleTimes:      86103,
	ErrorCodeServerError:               86150,
	ErrorCodePolicyViolationLowPlan:    86151,
	ErrorCodePolicyViolationDelinquent: 86152,
	ErrorCodeUserTorrentNotAllowed:     86153,
	ErrorCodeUserBadBehavior:           86154,
}

// Constants export constants for the client
func Constants() *Consts {
	return consts
}

type messageSocketFactory = func(
	clientCert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	log func(string),
) (*MessageSocket, error)

type AgentConnection struct {
	State  State
	Status *StatusMessage

	// private
	closed             bool
	closeChannel       chan bool
	connectivity       bool
	updateConnectivity chan bool
	client             NativeClient
	updateFeatures     chan bool
	requestedFeatures  Features
	featuresSent       bool
}

type NativeClient interface {
	Log(text string)
	OnState(state State)
	OnError(code int, description string)
	OnStatusUpdate(status *StatusMessage)
}

var initialBackoff = 250 * time.Millisecond
var maxBackoff = time.Minute
var backoffMultiplier = 4

//goland:noinspection GoUnusedExportedFunction
func NewAgentConnection(
	clientCertPEM,
	clientKeyPEM,
	serverCAsPEM string,
	host string,
	certServerName string,
	client NativeClient,
	features *Features,
	connectivity bool,
) (*AgentConnection, error) {
	return newAgentConnection(clientCertPEM, clientKeyPEM, serverCAsPEM, host, certServerName, client, features,
		connectivity, openSocket)
}

func newAgentConnection(
	clientCertPEM,
	clientKeyPEM,
	serverCAsPEM string,
	host string,
	certServerName string,
	client NativeClient,
	features *Features,
	connectivity bool,
	socketFactory messageSocketFactory,
) (*AgentConnection, error) {
	client.Log("LocalAgent: Connect")
	clientCert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
	if err != nil {
		client.Log("LocalAgent cert/key error: " + err.Error())
		return nil, err
	}
	conn := new(AgentConnection)
	conn.closed = false
	conn.connectivity = connectivity
	conn.updateConnectivity = make(chan bool, 1)
	conn.closeChannel = make(chan bool, 1)
	conn.client = client
	conn.updateFeatures = make(chan bool, 1)
	if features != nil {
		conn.requestedFeatures = *features
	} else {
		conn.requestedFeatures = *NewFeatures()
	}

	go conn.connectionLoop(clientCert, serverCAsPEM, host, certServerName, socketFactory)
	return conn, nil
}

func (conn *AgentConnection) Close() {
	if !conn.closed {
		conn.client.Log("LocalAgent: closing")
		conn.closed = true
		conn.setState(consts.StateDisconnected)
		go func() {
			conn.closeChannel <- true
		}()
	}
}

func (conn *AgentConnection) terminalState(state State) {
	conn.setState(state)
	<-conn.closeChannel
}

func (conn *AgentConnection) cleanup() {
	for len(conn.updateConnectivity) > 0 {
		<-conn.updateConnectivity
	}
	for len(conn.updateFeatures) > 0 {
		<-conn.updateFeatures
	}
	for len(conn.closeChannel) > 0 {
		<-conn.closeChannel
	}
	close(conn.updateConnectivity)
	close(conn.updateFeatures)
}

func (conn *AgentConnection) SetFeatures(features *Features) {
	conn.requestedFeatures.update(features)
	go func() {
		if !conn.closed {
			conn.updateFeatures <- true
		}
	}()
}

func (conn *AgentConnection) setState(state State) {
	conn.State = state
	conn.client.OnState(state)
}

func (conn *AgentConnection) SetConnectivity(available bool) {
	go func() {
		conn.connectivity = available
		if !conn.closed {
			conn.updateConnectivity <- available
		}
	}()
}

func (conn *AgentConnection) connectionLoop(
	cert tls.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	socketFactory messageSocketFactory,
) {
	nextBackoff := initialBackoff
	for !conn.closed {
		start := time.Now().Unix()

		for !conn.connectivity && !conn.closed {
			conn.client.Log("LocalAgent waiting for connectivity...")
			select {
			case <-conn.updateConnectivity:
			case <-conn.closeChannel:
				break
			}
		}

		if !conn.closed {
			err := conn.tlsConnectionLoop(cert, serverCAsPEM, host, certServerName, socketFactory)
			if !conn.closed {
				if err != nil {
					conn.client.Log("LocalAgent connection error: (" + fmt.Sprintf("%T", err) + ") " + err.Error())
					switch translateError(err) {
					case ErrorInvalidServerCert:
						conn.terminalState(consts.StateServerCertificateError)
					case ErrorExpiredCert:
						conn.terminalState(consts.StateClientCertificateError)
					case ErrorUnreachable:
						conn.setState(consts.StateServerUnreachable)
					default:
						conn.setState(consts.StateConnectionError)
					}
				}
				if !conn.closed {
					connectionTime := time.Duration(time.Now().Unix()-start) * time.Second
					// long connection reduces next backoff
					nextBackoff = minDuration(nextBackoff, maxBackoff-connectionTime)
					nextBackoff = maxDuration(initialBackoff, nextBackoff)
					nextBackoff += multiplyDuration(nextBackoff, 0.2*rand.Float64()) // random 0-20% increase

					hadConnectivity := conn.connectivity
					if hadConnectivity {
						conn.client.Log(fmt.Sprint("Local agent retry in ", nextBackoff.Seconds(), "s"))
					}
					select {
					case <-conn.closeChannel:
					case <-time.After(nextBackoff):
						break
					case <-conn.updateConnectivity:
						if conn.connectivity && !hadConnectivity {
							break
						}
						hadConnectivity = conn.connectivity
					}

					nextBackoff = minDuration(nextBackoff*time.Duration(backoffMultiplier), maxBackoff)
				}
			}
		}
	}
	conn.cleanup()
}

func (conn *AgentConnection) tlsConnectionLoop(
	cert tls.Certificate,
	serverCAsPEM,
	host string,
	certServerName string,
	socketFactory messageSocketFactory,
) (err error) {
	conn.setState(consts.StateConnecting)
	conn.client.Log("LocalAgent: establishing tls connection...")

	var socket *MessageSocket
	socket, err = socketFactory(cert, serverCAsPEM, host, certServerName, conn.client.Log)

	for len(conn.updateFeatures) > 0 {
		<-conn.updateFeatures
	}
	conn.featuresSent = false
	if !conn.closed && err == nil {
		conn.client.Log("LocalAgent: established tls connection")
		defer func() { socket.close <- true }()

		for err == nil && !conn.closed && conn.connectivity {
			select {
			case <-conn.updateFeatures:
				conn.sendFeaturesDiff(socket)
			case msg := <-socket.recv:
				err = conn.parse(msg, socket)
			case <-conn.updateConnectivity:
				{
					if !conn.connectivity {
						break
					}
				}
			case err = <-socket.recvErr:
			case err = <-socket.sendErr:
			case <-conn.closeChannel:
				break
			}
		}
	}
	return err
}

func (conn *AgentConnection) sendFeaturesDiff(socket *MessageSocket) {
	if conn.Status != nil {
		diff := conn.Status.Features.diffTo(&conn.requestedFeatures)
		if len(diff.fields) > 0 {
			conn.invalidateFeatures(diff)
			socket.send <- createMessage("features-set", diff)
		}
	}
}

func (conn *AgentConnection) invalidateFeatures(diff *Features) {
	if conn.Status != nil {
		for k := range diff.fields {
			delete(conn.Status.Features.fields, k)
		}
	}
}

func (conn *AgentConnection) parse(msgString string, socket *MessageSocket) error {
	var parsed map[string]json.RawMessage
	err := json.Unmarshal([]byte(msgString), &parsed)
	if err != nil {
		conn.client.Log("Local Agent: message parsing error " + err.Error())
	} else {
		for key := range parsed {
			value := parsed[key]
			var err error
			switch key {
			case "status":
				err = conn.parseStatus(value, socket)
			case "error":
				err = conn.parseError(value)
			default:
				conn.client.Log("Local Agent: unknown message type " + key)
			}
			if err != nil {
				conn.client.Log("Local Agent: error parsing message " + key + ": " + err.Error())
			}
		}
	}
	return err
}

func (conn *AgentConnection) parseStatus(rawStatus json.RawMessage, socket *MessageSocket) error {
	var status StatusMessage
	err := json.Unmarshal(rawStatus, &status)
	if err != nil {
		return err
	}

	conn.Status = &status
	switch status.State {
	case "jailed":
		conn.setState(consts.StateSoftJailed)
	case "hard-jailed":
		conn.setState(consts.StateHardJailed)
	case "connected":
		conn.setState(consts.StateConnected)
	}
	conn.client.OnStatusUpdate(&status)
	if conn.Status.Reason != nil {
		conn.client.OnError(conn.Status.Reason.Code, conn.Status.Reason.Description)
	}

	if !conn.featuresSent {
		conn.sendFeaturesDiff(socket)
		conn.featuresSent = true
	}

	return nil
}

func (conn *AgentConnection) parseError(rawError json.RawMessage) error {
	var errorMsg ErrorMessage
	err := json.Unmarshal(rawError, &errorMsg)
	if err != nil {
		return err
	}

	conn.client.OnError(errorMsg.Code, errorMsg.Description)
	return nil
}
