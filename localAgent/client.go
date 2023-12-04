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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type ErrorCode = int

type Consts struct {
	// States
	StateConnecting                    string
	StateConnected                     string
	StateSoftJailed                    string
	StateHardJailed                    string
	StateConnectionError               string
	StateServerUnreachable             string
	StateWaitingForNetwork             string
	StateServerCertificateError        string
	StateClientCertificateExpiredError string
	StateClientCertificateUnknownCA    string
	StateDisconnected                  string

	// Error codes
	ErrorCodeUnknown                   int
	ErrorCodeGuestSession              int
	ErrorCodeRestrictedServer          int
	ErrorCodeBadCertSignature          int
	ErrorCodeCertNotProvided           int
	ErrorCodeCertificateExpired        int
	ErrorCodeCertificateRevoked        int
	ErrorCodeMaxSessionsUnknown        int
	ErrorCodeMaxSessionsFree           int
	ErrorCodeMaxSessionsBasic          int
	ErrorCodeMaxSessionsPlus           int
	ErrorCodeMaxSessionsVisionary      int
	ErrorCodeMaxSessionsPro            int
	ErrorCodeKeyUsedMultipleTimes      int
	ErrorCodeServerError               int
	ErrorCodePolicyViolationLowPlan    int
	ErrorCodePolicyViolationDelinquent int
	ErrorCodeUserTorrentNotAllowed     int
	ErrorCodeUserBadBehavior           int

	LabelPartner    string
	FeatureBouncing string

	// Stats
	StatsNetshieldLevelKey string
	StatsMalwareKey        string
	StatsAdsKey            string
	StatsTrackerKey        string
	StatsSavedBytesKey     string

	// NOTE: initialize in var consts when adding new
}

var consts = &Consts{
	StateConnecting:                    "Connecting",
	StateConnected:                     "Connected",
	StateSoftJailed:                    "SoftJailed",
	StateHardJailed:                    "HardJailed",
	StateConnectionError:               "ConnectionError",
	StateServerUnreachable:             "ServerUnreachable",
	StateWaitingForNetwork:             "WaitingForNetwork",
	StateServerCertificateError:        "ServerCertificateError",
	StateClientCertificateExpiredError: "ClientCertificateExpiredError",
	StateClientCertificateUnknownCA:    "ClientCertificateUnknownCA",
	StateDisconnected:                  "Disconnected",

	ErrorCodeUnknown:                   0,
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

	LabelPartner:    "partner",
	FeatureBouncing: "bouncing",

	StatsNetshieldLevelKey: "netshield-level",
	StatsMalwareKey:        "DNSBL/1b",
	StatsAdsKey:            "DNSBL/2a",
	StatsTrackerKey:        "DNSBL/2b",
	StatsSavedBytesKey:     "savedBytes",
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
	State  string
	Status *StatusMessage

	// private
	closed             atomic.Bool
	closeChannel       chan struct{}
	cleanupWg          sync.WaitGroup
	connectivity       bool
	updateConnectivity chan bool
	client             NativeClient
	updateFeatures     chan bool
	getStatusRequests  chan bool
	requestedFeatures  Features
	featuresSent       bool
}

type NativeClient interface {
	Log(text string)
	OnState(state string)
	OnError(code int, description string)
	OnStatusUpdate(status *StatusMessage)
	OnTlsSessionStarted()
	OnTlsSessionEnded()
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
	keepAliveSeconds int, // 0 sets Go defaults
	keepAliveMaxCount int, // 0 sets Go defaults
) (*AgentConnection, error) {
	socketFactory := func(
		clientCert tls.Certificate,
		serverCAsPEM string,
		host string,
		certServerName string,
		log func(string),
	) (*MessageSocket, error) {
		return openSocket(clientCert, serverCAsPEM, host, certServerName, keepAliveSeconds, keepAliveMaxCount, log)
	}
	return newAgentConnection(clientCertPEM, clientKeyPEM, serverCAsPEM, host, certServerName, client, features,
		connectivity, socketFactory)
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
	leafCert, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		client.Log("LocalAgent leaf certificate error: " + err.Error())
		return nil, err
	}
	conn := new(AgentConnection)
	conn.closed.Store(false)
	conn.connectivity = connectivity
	conn.updateConnectivity = make(chan bool, 1)
	conn.closeChannel = make(chan struct{})
	conn.client = client
	conn.updateFeatures = make(chan bool, 1)
	conn.getStatusRequests = make(chan bool, 1)
	if features != nil {
		conn.requestedFeatures = *features
	} else {
		conn.requestedFeatures = *NewFeatures()
	}

	go conn.connectionLoop(clientCert, leafCert, serverCAsPEM, host, certServerName, socketFactory)
	return conn, nil
}

func (conn *AgentConnection) Close() {
	if conn.closed.CompareAndSwap(false, true) {
		conn.client.Log("LocalAgent: closing")
		conn.setState(consts.StateDisconnected)
		close(conn.closeChannel)
	}
}

func (conn *AgentConnection) terminalState(state string) {
	conn.setState(state)
	<-conn.closeChannel
}

func (conn *AgentConnection) cleanup() {
	<-conn.closeChannel
	conn.cleanupWg.Wait()
	close(conn.updateConnectivity)
	close(conn.updateFeatures)
	close(conn.getStatusRequests)
}

func (conn *AgentConnection) SetFeatures(features *Features) {
	conn.requestedFeatures.update(features)
	conn.cleanupWg.Add(1)
	go func() {
		defer conn.cleanupWg.Done()
		select {
		case conn.updateFeatures <- true:
		case <-conn.closeChannel:
		}
	}()
}

func (conn *AgentConnection) SendGetStatus(withStatistics bool) {
	conn.cleanupWg.Add(1)
	go func() {
		defer conn.cleanupWg.Done()
		select {
		case conn.getStatusRequests <- withStatistics:
		case <-conn.closeChannel:
		}
	}()
}

func (conn *AgentConnection) setState(state string) {
	conn.State = state
	conn.client.OnState(state)
}

func (conn *AgentConnection) SetConnectivity(available bool) {
	conn.cleanupWg.Add(1)
	go func() {
		defer conn.cleanupWg.Done()
		conn.connectivity = available
		select {
		case conn.updateConnectivity <- available:
		case <-conn.closeChannel:
		}
	}()
}

func (conn *AgentConnection) connectionLoop(
	cert tls.Certificate,
	leafCert *x509.Certificate,
	serverCAsPEM string,
	host string,
	certServerName string,
	socketFactory messageSocketFactory,
) {
	nextBackoff := initialBackoff
	for !conn.closed.Load() {
		start := time.Now().Unix()

		for !conn.connectivity && !conn.closed.Load() {
			conn.client.Log("LocalAgent waiting for connectivity...")
			conn.setState(consts.StateWaitingForNetwork)
			select {
			case <-conn.updateConnectivity:
			case <-conn.closeChannel:
				break
			}
		}

		if !conn.closed.Load() {
			err := conn.tlsConnectionLoop(cert, serverCAsPEM, host, certServerName, socketFactory)
			if !conn.closed.Load() {
				if err != nil {
					conn.client.Log("LocalAgent connection error: (" + fmt.Sprintf("%T", err) + ") " + err.Error())
					switch translateError(err) {
					case ErrorInvalidServerCert:
						conn.terminalState(consts.StateServerCertificateError)
					case ErrorClientCertExpired:
						conn.terminalState(consts.StateClientCertificateExpiredError)
					case ErrorClientCertUnknownCA:
						conn.terminalState(consts.StateClientCertificateUnknownCA)
					case ErrorUnreachable:
						conn.setState(consts.StateServerUnreachable)
					default:
						if time.Now().After(leafCert.NotAfter) {
							conn.terminalState(consts.StateClientCertificateExpiredError)
						} else {
							conn.setState(consts.StateConnectionError)
						}
					}
				}
				if !conn.closed.Load() {
					connectionTime := time.Duration(time.Now().Unix()-start) * time.Second
					// long connection reduces next backoff
					nextBackoff = minDuration(nextBackoff, maxBackoff-connectionTime)
					nextBackoff = maxDuration(initialBackoff, nextBackoff)
					nextBackoff += multiplyDuration(nextBackoff, 0.2*rand.Float64()) // #nosec G404 random 0-20% increase

					if conn.connectivity {
						conn.client.Log(fmt.Sprint("Local agent retry in ", nextBackoff.Seconds(), "s"))
						select {
						case <-conn.closeChannel:
						case <-time.After(nextBackoff):
							break
						case <-conn.updateConnectivity:
							if !conn.connectivity {
								break
							}
						}
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
	if err == nil {
		defer func() { socket.close <- true }()
		if !conn.closed.Load() {
			conn.client.Log("LocalAgent: established tls connection")

			conn.client.OnTlsSessionStarted()
			for err == nil && !conn.closed.Load() && conn.connectivity {
				select {
				case <-conn.updateFeatures:
					conn.sendFeaturesDiff(socket)
				case withStatistics := <-conn.getStatusRequests:
					conn.sendGetStatus(socket, withStatistics)
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
			conn.client.OnTlsSessionEnded()
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

func (conn *AgentConnection) sendGetStatus(socket *MessageSocket, withStatistics bool) {
	socket.send <- createMessage("status-get", GetStatusMessage{FeaturesStatistics: withStatistics})
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

	if status.State == "hard-jailed" && status.Reason != nil && status.Reason.Code == consts.ErrorCodePolicyViolationLowPlan && conn.requestedFeatures.hasPartnerLabel() {
		// Partner servers operate with jail, pretend everything's fine.
		status.State = "connected"
		status.Reason = nil
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
	status.processStats()
	conn.client.OnStatusUpdate(&status)
	if conn.Status.Reason != nil {
		conn.client.OnError(conn.Status.Reason.Code, conn.Status.Reason.Description)
	} else if status.State == "hard-jailed" {
		conn.client.OnError(consts.ErrorCodeUnknown, "")
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

func (features *Features) hasPartnerLabel() bool {
	return features.GetStringOrDefault(consts.FeatureBouncing, "") == consts.LabelPartner
}
