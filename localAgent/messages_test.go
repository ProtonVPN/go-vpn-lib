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
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testFeatures = createTestFeatures()

var statusNetshieldStatsJson = `{
        "state": "connected",
        "features": {
            "bouncing": "0",
            "randomized-nat": false,
            "split-tcp": true,
            "netshield-level": 2
        },
        "features-statistics": {
            "netshield-level": {
                "DNSBL/1b": 1,
                "DNSBL/2a": 2
            }
        }
    }`

var statusUnknownStatsJson = `{
		"state": "connected",
		"features": {
			"bouncing": "0",
			"randomized-nat": false,
			"split-tcp": true,
			"netshield-level": 2
		},
		"features-statistics": {
			"unknown-group": {
				"a": 1
			}
		}
	}`

func createTestFeatures() *Features {
	var feat = NewFeatures()
	feat.SetInt("int", 2)
	feat.SetInt("int2", 3)
	feat.SetBool("bool", true)
	feat.SetString("string", "1")
	return feat
}

func TestFeatures(t *testing.T) {
	assert := assert.New(t)

	bytes, _ := json.Marshal(testFeatures)

	var unmarshalled Features
	json.Unmarshal(bytes, &unmarshalled)

	assert.Equal(4, unmarshalled.GetKeys().GetCount())
	assert.Equal(toSet([]string{"int", "int2", "bool", "string"}), toSet(unmarshalled.GetKeys().values))
	assert.Equal(int64(2), unmarshalled.GetInt("int"))
	assert.Equal(int64(3), unmarshalled.GetInt("int2"))
	assert.Equal(true, unmarshalled.GetBool("bool"))
	assert.Equal("1", unmarshalled.GetString("string"))
	assert.True(unmarshalled.HasKey("string"))
	assert.False(unmarshalled.HasKey("unknown"))
}

func Test_CreateMessage(t *testing.T) {
	assert := assert.New(t)
	msg := createMessage("status-get", map[string]int{"key": 1})
	assert.Equal("{\"status-get\":{\"key\":1}}", msg)
}

func toSet(values []string) map[string]bool {
	var result = make(map[string]bool)
	for _, v := range values {
		result[v] = true
	}
	return result
}

func TestNetshieldStatsParsingAndProcessing(t *testing.T) {
	assert := assert.New(t)
	var status StatusMessage
	err := json.Unmarshal([]byte(statusNetshieldStatsJson), &status)
	assert.Equal(nil, err)
	status.processStats()
	var stats = status.FeaturesStatistics.GetMap(consts.StatsNetshieldLevelKey)
	var savedKB = stats.GetInt(consts.StatsSavedBytesKey)
	assert.Equal(avgMalwareSizeBytes + 2 * avgAdSizeBytes, savedKB)
}

func TestUnknownStats(t *testing.T) {
	assert := assert.New(t)
	var status StatusMessage
	err := json.Unmarshal([]byte(statusUnknownStatsJson), &status)
	assert.Equal(nil, err)
	status.processStats()
	var unknownStat = status.FeaturesStatistics.GetMap("unknown-group").GetInt("a")
	assert.Equal(int64(1), unknownStat)
}