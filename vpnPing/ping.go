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

package vpnPing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

func PingSync(ip string, port int, serverKeyBase64 string, timeoutMilliseconds int) bool {
	result, err := PingSyncWithError(ip, port, serverKeyBase64, timeoutMilliseconds)
	if err != nil {
		println("PingSync error: " + err.Error())
	}
	return result
}

func PingSyncWithError(ip string, port int, serverKeyBase64 string, timeoutMilliseconds int) (bool, error) {
	key, err := base64.StdEncoding.DecodeString(serverKeyBase64)
	if err != nil {
		return false, err
	}

	// Encode in little endian the current unix timestamp. This would work until 2038.
	timestamp := uint32(time.Now().Unix())

	msg := new(bytes.Buffer)
	msg.Write(key)
	binary.Write(msg, binary.LittleEndian, timestamp)

	hmac := hmac.New(sha256.New, []byte("lci6UYRryo5rcQVpxfJ0fCs6UBY5eGyV"))
	hmac.Write(msg.Bytes())

	data := new(bytes.Buffer)
	// FE is an invalid opcode for both OpenVPN and Wireguard, 01 is the version of the ping
	data.Write([]byte{0xfe, 0x01})
	binary.Write(data, binary.LittleEndian, timestamp)
	data.Write(hmac.Sum(nil))

	address := fmt.Sprint(ip, ":", port)
	result := make([]byte, 3)
	err = pingUDP(address, timeoutMilliseconds, data.Bytes(), result)
	if err != nil {
		return false, err
	}

	if bytes.Compare(result, []byte{0xfe, 0x01, 0x01}) != 0 {
		return false, errors.New(fmt.Sprint("PingSync: unexpected response from ", ip, ":", port))
	}
	return true, nil
}

func pingUDP(address string, timeoutMilliseconds int, data []byte, result []byte) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return err
	}

	defer conn.Close()

	deadline := time.Now().Add(time.Millisecond * time.Duration(timeoutMilliseconds))
	err = conn.SetDeadline(deadline)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	_, err = conn.Read(result)
	if err != nil {
		return err
	}

	return nil
}
