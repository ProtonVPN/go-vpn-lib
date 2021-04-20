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

package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

var ed25519PKIXPublicPrefix = []byte{0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00}
var ed25519PKIXPrivatePrefix = []byte{0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}

type KeyPair struct {
	private ed25519.PrivateKey
}

// CreateKeyPair creates KeyPair based on provided private and public keys. Only for test use.
func CreateKeyPair(pri []byte, pub []byte) *KeyPair {
	key, _ := NewKeyPair()
	copy(key.private[:ed25519.SeedSize], pri)
	copy(key.private[ed25519.SeedSize:], pub)
	return key
}

// NewKeyPair generates new ED25519 key pair
func NewKeyPair() (*KeyPair, error) {
	_, pri, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &KeyPair{pri}, nil
}

func (key KeyPair) PublicKeyBytes() []byte {
	return key.private[ed25519.SeedSize:]
}

func (key KeyPair) PrivateKeyBytes() []byte {
	return key.private.Seed()
}

// PublicKeyPKIX returns public key in PKIX, ASN.1 DER format
func (key KeyPair) PublicKeyPKIX() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key.private.Public())
}

// PrivateKeyPKIX private key in PKIX, ASN.1 DER format
func (key KeyPair) PrivateKeyPKIX() []byte {
	return append(ed25519PKIXPrivatePrefix[:], key.PrivateKeyBytes()...)
}

// PublicKeyPKIXBase64 public key in PKIX, ASN.1 DER in Base64
func (key KeyPair) PublicKeyPKIXBase64() (string, error) {
	bytes, err := key.PublicKeyPKIX()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// PrivateKeyPKIXBase64 returns private key PKIX, ASN.1 DER in Base64
func (key KeyPair) PrivateKeyPKIXBase64() string {
	return base64.StdEncoding.EncodeToString(key.PrivateKeyPKIX())
}

// PublicKeyPKIXPem returns public key in ASN.1 DER representation as PEM
func (key KeyPair) PublicKeyPKIXPem() (string, error) {
	bytes, err := key.PublicKeyPKIX()
	if err != nil {
		return "", err
	}
	return toPEM(bytes, "PUBLIC KEY"), nil
}

// PrivateKeyPKIXPem returns private key ASN.1 DER representation as PEM
func (key KeyPair) PrivateKeyPKIXPem() string {
	return toPEM(key.PrivateKeyPKIX(), "PRIVATE KEY")
}

// ToX25519 converts to X25519 secret key.
func (key KeyPair) ToX25519() []byte {
	hash := sha512.Sum512(key.PrivateKeyBytes())
	hash[0] &= 0xF8
	hash[31] &= 0x7F
	hash[31] |= 0x40
	return hash[:32]
}

// ToX25519Base64 converts to X25519 secret key encoded as base64.
func (key KeyPair) ToX25519Base64() string {
	return base64.StdEncoding.EncodeToString(key.ToX25519())
}

func toPEM(bytes []byte, header string) string {
	encoded := pem.EncodeToMemory(
		&pem.Block{
			Type:  header,
			Bytes: bytes,
		},
	)
	return string(encoded)
}
