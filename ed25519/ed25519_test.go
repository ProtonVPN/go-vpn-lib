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
	"github.com/stretchr/testify/assert"
	"testing"
)

var privateTest = []byte{
	0x9d, 0x68, 0x0d, 0xf3, 0x05, 0xff, 0x5b, 0x10, 0xdb, 0x5b, 0xa0, 0xdc, 0xcb, 0x6c, 0x47, 0x88,
	0x12, 0xfd, 0xf4, 0x8a, 0xad, 0x08, 0xe9, 0x96, 0xd1, 0x9a, 0x28, 0xf3, 0xb3, 0x2e, 0xb2, 0x56,
}

var publicTest = []byte{
	0x4b, 0x90, 0xa4, 0x72, 0x8e, 0x94, 0x7a, 0xea, 0xad, 0x8c, 0x2a, 0xe5, 0xf9, 0xf6, 0xcf, 0xd5,
	0xaf, 0x75, 0x1b, 0x7d, 0x9d, 0xc8, 0xe8, 0x16, 0x13, 0xe4, 0x61, 0xed, 0xf6, 0x64, 0x8c, 0x89,
}

var testKey = createKeyPair(privateTest, publicTest)

// createKeyPair creates KeyPair based on provided private and public keys. Only for test use.
func createKeyPair(pri []byte, pub []byte) *KeyPair {
	private := make([]byte, 2*ed25519.SeedSize)
	copy(private[:ed25519.SeedSize], pri)
	copy(private[ed25519.SeedSize:], pub)
	return &KeyPair{private}
}

func TestKeyPair_PemKeys(t *testing.T) {
	assert := assert.New(t)

	expectedPrivatePem :=
		"-----BEGIN PRIVATE KEY-----\n" +
			"MC4CAQAwBQYDK2VwBCIEIJ1oDfMF/1sQ21ug3MtsR4gS/fSKrQjpltGaKPOzLrJW\n" +
			"-----END PRIVATE KEY-----\n"
	assert.Equal(expectedPrivatePem, testKey.PrivateKeyPKIXPem())

	expectedPublicPem :=
		"-----BEGIN PUBLIC KEY-----\n" +
			"MCowBQYDK2VwAyEAS5Ckco6UeuqtjCrl+fbP1a91G32dyOgWE+Rh7fZkjIk=\n" +
			"-----END PUBLIC KEY-----\n"
	publicPem, _ := testKey.PublicKeyPKIXPem()
	assert.Equal(expectedPublicPem, publicPem)
}

func TestKeyPair_ToX25519Base64(t *testing.T) {
	assert := assert.New(t)
	expectedX25519 := "uDiY1T9gYZO90r2fC63At9T2CnV1X8/NfWaQ/v/gT2g="
	assert.Equal(expectedX25519, testKey.ToX25519Base64())
}
