package main

import (
	"C"
	"encoding/json"
	"go-vpn-lib/localAgent"
	"go-vpn-lib/vpnPing"
	"strings"
)

var currentConnection *localAgent.AgentConnection
var currentClient *WindowsClient

type WindowsClient struct {
	localAgent.NativeClient
	eventChannel chan *Event
}

type ConnectionDetailsType struct {
	DeviceIp        string
	DeviceCountry   string
	ServerIpv4      string
	ServerIpv6      string
}

type Event struct {
	EventType           string
	Log                 string
	State               string
	Code                int
	Desc                string
	ConnectionDetails   *ConnectionDetailsType
	FeaturesStatistics	string
}

func (c *WindowsClient) Log(log string) {
	c.eventChannel <- &Event{EventType: "log", Log: log}
}

func (c *WindowsClient) OnState(s localAgent.State) {
	c.eventChannel <- &Event{EventType: "state", State: s}
}

func (c *WindowsClient) OnError(code int, desc string) {
	c.eventChannel <- &Event{EventType: "error", Code: code, Desc: desc}
}

func (c *WindowsClient) OnStatusUpdate(status *localAgent.StatusMessage) {
	var connectionDetails *ConnectionDetailsType
	if status.ConnectionDetails != nil {
		connectionDetails = &ConnectionDetailsType {
			DeviceIp: status.ConnectionDetails.DeviceIp,
			DeviceCountry: status.ConnectionDetails.DeviceCountry,
			ServerIpv4: status.ConnectionDetails.ServerIpv4,
			ServerIpv6: status.ConnectionDetails.ServerIpv6,
		}
	}

	c.eventChannel <- &Event{EventType: "status", ConnectionDetails: connectionDetails}

	var featuresStatistics []byte
	if status.FeaturesStatistics != nil {
		featuresStatistics, _ = status.FeaturesStatistics.MarshalJSON()
	}
	if featuresStatistics != nil {
		c.eventChannel <- &Event{EventType: "stats", FeaturesStatistics: string(featuresStatistics)}
	}
}

func (c *WindowsClient) OnTlsSessionStarted() {
}

func (c *WindowsClient) OnTlsSessionEnded() {
}

//export Connect
func Connect(
	clientCertPEM,
	clientKeyPEM,
	serverCAsPEM,
	host,
	certServerName,
	featuresJson string,
	connectivity bool,
) []byte {

	var clientCertPEMCopy = deepCopy(clientCertPEM)
	var clientKeyPEMCopy = deepCopy(clientKeyPEM)
	var serverCAsPEMCOpy = deepCopy(serverCAsPEM)
	var hostCopy = deepCopy(host)
	var certServerNameCopy = deepCopy(certServerName)
	var featuresJsonCopy = deepCopy(featuresJson)
	var features *localAgent.Features
	var err error

	if len(featuresJsonCopy) > 0 {
		err := json.Unmarshal([]byte(featuresJsonCopy), &features)
		if err != nil {
			return []byte(err.Error())
		}
	}
	currentClient = new(WindowsClient)
	currentClient.eventChannel = make(chan *Event, 10)
	currentConnection, err = localAgent.NewAgentConnection(
		clientCertPEMCopy, clientKeyPEMCopy, serverCAsPEMCOpy, hostCopy, certServerNameCopy, currentClient,
		features, connectivity)
	if err != nil {
		currentConnection = nil
		return []byte(err.Error())
	}
	return []byte("")
}

//export GetEvent
func GetEvent() []byte {
	client := currentClient
	if client == nil {
		return []byte("")
	}
	event := <-client.eventChannel
	if event == nil {
		return []byte("")
	}
	result, _ := json.Marshal(event)
	return []byte(string(result))
}

//export GetStatus
func GetStatus() []byte {
	result, _ := json.Marshal(currentConnection.Status)
	return []byte(string(result))
}

//export SendGetStatus
func SendGetStatus(withStatistics bool) {
	currentConnection.SendGetStatus(withStatistics)
}

//export SetFeatures
func SetFeatures(featuresJson string) {
	features := new(localAgent.Features)
	json.Unmarshal([]byte(featuresJson), &features)
	currentConnection.SetFeatures(features)
}

//export SetConnectivity
func SetConnectivity(connectivity bool) {
	currentConnection.SetConnectivity(connectivity)
}

//export Close
func Close() {
	currentConnection.Close()
	currentConnection = nil
	close(currentClient.eventChannel)
	currentClient = nil
}

//export Ping
func Ping(ip string, port int, serverKeyBase64 string, timeoutSeconds int) bool {
	return vpnPing.PingSync(ip, port, serverKeyBase64, timeoutSeconds)
}

func deepCopy(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	return sb.String()
}

func main() {}
