# Clients shared library for Wireguard

## Ed25519 tools

Package `ed25519` contains key generation / conversion tools for `Ed25519` key pairs. Example usage in kotlin:
```kotlin
val keyPair = ed25519.KeyPair()

keyPair.publicKeyPKIXPem()
// -----BEGIN PUBLIC KEY-----
// MCowBQYDK2VwAyEAAovbYY+fPynudXXSYCoHjtJOaUHaFL2WoxKxBFUKLCQ=
// -----END PUBLIC KEY-----

keyPair.toX25519Base64()
// cGYCiCkQaOjc23dpDbKO7NkSjj79p9MJLWoukc2Zkkw=
```

## State Machine for Local Agent

Package `localAgent` enables connecting to Local Agents running on our VPN servers. Usage:
```kotlin
val nativeClient = object: NativeClient {
    override fun log(msg: String) {
        // Debug logs coming from the library
    }

    override fun onError(code: Long, description: String) {
        // On error message received from Local Agent
    }

    override fun onState(state: String) {
        // Constants for states etc.
        val consts = localAgent.LocalAgent.constants()
        when (state) {
            consts.stateConnecting -> ...
            consts.stateHardJailed -> {
                when (agent.status.reason.code) {
                    consts.errorCodeCertificateRevoked ->
                        // regenerate key and certificate and create new AgentConnection
                }
            }
            ...
        }
    }
}

// Initial features sent to agent
val features = localAgent.Features()
features.setInt("netshield-level", 1)
features.setBool("jail", true)

// After establishing a VPN tunnel with our server
agent = localAgent.AgentConnection(clientCertPEM, clientPrivateKeyPEM, serverRootCerts, "ip:port", nativeClient, features)

agent.status // last received status message or null

// Update features and unjail
features.setInt("netshield-level", 2)
features.setBool("jail", false)
agent.setFeatures(features)

// Update connectivity
agent.setConnectivity(false) // no internet, tls connection restarts will pause until connectivity is back
...
agent.setConnectivity(true) // internet back

agent.close() // closes connection with agent
```
## Build instructions for Android

* Install golang (https://golang.org/doc/install)
* Install gomobile
```bash
$ go get golang.org/x/mobile/cmd/gomobile
$ gomobile init
```
* clone go-srp in the root dir of this project
```bash
$ cd go-vpn-lib
$ git clone https://github.com/ProtonMail/go-srp.git
```
* build library with gomobile
```bash
$ gomobile bind -o govpn.aar ./ed25519 ./localAgent ./go-srp ...
```

## Build instructions for Apple platforms (iOS and macOS)

### Dependencies

**Go**

Install Go

```bash
brew install go
```

**Proton Go Mobile build script**

Get the Proton Go Mobile build 

```bash
git clone git@gitlab.protontech.ch:crypto/gomobile-build-script.git
``` 

(we are going to assume you cloned it into `~/Projects/Proton/gomobile-build-script`)

### Get the code

Clone this repository 

```bash
git clone git@github.com/ProtonVPN/go-vpn-lib.git
```

(we are going to assume you cloned it into `~/Projects/Proton/VPN/go-vpn-lib`). 

Go Mobile can only build code form public repositories. This repository is private so you need to clone it locally and use it for the build locally.

In the cloned repository 

```bash
cd ~/Projects/Proton/VPN/go-vpn-lub
```

initialize a Go module

```bash
go mod init github.com/ProtonVPN/go-vpn-lib
```

### Build config

The build config is located in `~/Projects/Proton/VPN/go-vpn-lub/build/apple.json` but needs to be adjusted manually. 

This config is set up to build the library for iOS and macOS together with the SRP library. Any app can only contain one Go Mobile library and the VPN app also needs the SRP library. Because of this you need to build one Go Mobile library that contains both SRP and the clients shared library for Wireguard.

First make sure the `go_version` in `build/apple.json` matches the Go version you installed. You can check the Go version with `go version`. 

Then change the `local_path` in the `replacements` section to the full path of the folder where you cloned this repository

```json
"local_path":"/absolute/path/to/go-vpn-lib/"
```

### Build

Enter the folder where you cloned the Proton Go Mobile build script

```bash
cd ~/Projects/Proton/gomobile-build-script
```

and execute the build command pointing to the edited build config

```bash
make build cfg=~/Projects/Proton/VPN/go-vpn-lib/build/apple.json
```

### License
The code and datafiles in this distribution are licensed under the terms of the GPLv3 as published by the Free Software Foundation. See https://www.gnu.org/licenses/ for a copy of this license.

Copyright (c) 2021 Proton Technologies AG