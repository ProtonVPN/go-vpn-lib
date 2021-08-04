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
	"github.com/pkg/errors"
)

type KeyPair struct {
	private ed25519.PrivateKey
}

// NewKeyPair generates new ED25519 key pair
func NewKeyPair() (*KeyPair, error) {
	_, pri, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, errors.Wrap(err, "ed25519: unable to generate key pair")
	}
	return &KeyPair{pri}, nil
}

// Clear clears memory storing key pair
func (key KeyPair) Clear() {
	for i := range key.private {
		key.private[i] = 0
	}
}

func (key KeyPair) PublicKeyBytes() []byte {
	return key.private[ed25519.SeedSize:]
}

func (key KeyPair) PrivateKeyBytes() []byte {
	return key.private.Seed()
}

// PublicKeyPKIX returns public key in PKIX, ASN.1 DER format
func (key KeyPair) PublicKeyPKIX() ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key.private.Public())
	if err != nil {
		return nil, errors.Wrap(err, "ed25519: failed marshalling of public key")
	}
	return bytes, nil
}

// PrivateKeyPKIX private key in PKIX, ASN.1 DER format
func (key KeyPair) PrivateKeyPKIX() []byte {
	return append(Ed25519PKIXPrivatePrefix[:], key.PrivateKeyBytes()...)
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
