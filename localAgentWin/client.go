package main

import (
	"../localAgent"
	"C"
	"encoding/json"
	"strings"
)

var currentConnection *localAgent.AgentConnection
var currentClient *WindowsClient

type WindowsClient struct {
	localAgent.NativeClient
	eventChannel chan *Event
}

type Event struct {
	EventType string
	Log       string
	State     string
	Code      int
	Desc      string
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

//export Connect
func Connect(
	clientCertPEM,
	clientKeyPEM,
	serverCAsPEM,
	host,
	certServerName,
	featuresJson string,
	connectivity bool,
) string {

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
			return err.Error()
		}
	}
	currentClient = new(WindowsClient)
	currentClient.eventChannel = make(chan *Event, 10)
	currentConnection, err = localAgent.NewAgentConnection(
		clientCertPEMCopy, clientKeyPEMCopy, serverCAsPEMCOpy, hostCopy, certServerNameCopy, currentClient,
		features, connectivity)
	if err != nil {
		currentConnection = nil
		return err.Error()
	}
	return ""
}

//export GetEvent
func GetEvent() string {
	client := currentClient
	if client == nil {
		return ""
	}
	event := <-client.eventChannel
	if event == nil {
		return ""
	}
	result, _ := json.Marshal(event)
	return string(result)
}

//export GetStatus
func GetStatus() string {
	result, _ := json.Marshal(currentConnection.Status)
	return string(result)
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

func deepCopy(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	return sb.String()
}

func main() {}
