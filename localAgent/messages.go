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

import "encoding/json"

var avgAdSizeBytes int64 = 200 * 1024
var avgTrackerSizeBytes int64 = 50 * 1024
var avgMalwareSizeBytes int64 = 750 * 1024

type ErrorMessage struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type StringToValueMap struct {
	fields map[string]interface{}
}

type Features struct {
	StringToValueMap
}

//goland:noinspection GoUnusedExportedFunction
func NewFeatures() *Features {
	result := new(Features)
	result.fields = map[string]interface{}{}
	return result
}

func (feat *StringToValueMap) UnmarshalJSON(data []byte) error {
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	feat.fields = fields
	return nil
}

func (feat *StringToValueMap) MarshalJSON() ([]byte, error) {
	return json.Marshal(feat.fields)
}

func (feat *StringToValueMap) HasKey(name string) bool {
	_, ok := feat.fields[name]
	return ok
}

func (feat *StringToValueMap) GetCount() int {
	return len(feat.fields)
}

func (feat *StringToValueMap) GetKeys() *StringArray {
	result := make([]string, 0, len(feat.fields))
	for key := range feat.fields {
		result = append(result, key)
	}
	return &StringArray{values: result}
}

func (feat *StringToValueMap) Remove(key string) {
	delete(feat.fields, key)
}

func (feat *StringToValueMap) SetInt(name string, value int64) {
	feat.fields[name] = float64(value)
}

func (feat *StringToValueMap) GetInt(name string) int64 {
	return int64(feat.fields[name].(float64))
}

func (feat *StringToValueMap) GetIntOrDefault(name string, defautVal int64) int64 {
	if v, ok := feat.fields[name]; ok {
		return int64(v.(float64))
	}
	return defautVal
}

func (feat *StringToValueMap) SetString(name string, value string) {
	feat.fields[name] = value
}

func (feat *StringToValueMap) GetString(name string) string {
	return feat.fields[name].(string)
}

func (feat *StringToValueMap) GetStringOrDefault(name string, defaultVal string) string {
	if v, ok := feat.fields[name]; ok {
		return v.(string)
	}
	return defaultVal
}

func (feat *StringToValueMap) SetBool(name string, value bool) {
	feat.fields[name] = value
}

func (feat *StringToValueMap) GetBool(name string) bool {
	return feat.fields[name].(bool)
}

func (feat *StringToValueMap) GetMap(name string) *StringToValueMap {
	return &StringToValueMap{fields: feat.fields[name].(map[string]interface{})}
}

func (feat *StringToValueMap) update(other *Features) {
	for k, v := range other.fields {
		feat.fields[k] = v
	}
}

func (feat *StringToValueMap) diffTo(other *Features) *Features {
	result := NewFeatures()
	for k, v := range other.fields {
		if feat.fields[k] != v {
			result.fields[k] = v
		}
	}
	return result
}

type StatusMessage struct {
	State              string             `json:"state"`
	Features           *Features          `json:"features"`
	Reason             *Reason            `json:"reason"`
	SwitchTo           string             `json:"please-switch-to"`
	ConnectionDetails  *ConnectionDetails `json:"connection-details"`
	FeaturesStatistics *StringToValueMap  `json:"features-statistics"`
}

func (status *StatusMessage) processStats() {
	var stats = status.FeaturesStatistics
	if stats != nil {
		if stats.HasKey(consts.StatsNetshieldLevelKey) {
			var netshieldStats = status.FeaturesStatistics.GetMap(consts.StatsNetshieldLevelKey)
			var malwareBlocked = netshieldStats.GetIntOrDefault(consts.StatsMalwareKey, 0)
			var adsBlocked = netshieldStats.GetIntOrDefault(consts.StatsAdsKey, 0)
			var trackersBlocked = netshieldStats.GetIntOrDefault(consts.StatsTrackerKey, 0)
			var statsSavedBytes =
				avgAdSizeBytes * adsBlocked +
				avgTrackerSizeBytes * trackersBlocked +
				avgMalwareSizeBytes * malwareBlocked
			netshieldStats.SetInt(consts.StatsSavedBytesKey, statsSavedBytes)
		}
	}
}

type Reason struct {
	Code        int    `json:"code"`
	Final       bool   `json:"final"`
	Description string `json:"description"`
}

type ConnectionDetails struct {
	DeviceIp      string `json:"device-ip"`
	DeviceCountry string `json:"device-country"`
	ServerIpv4    string `json:"server-ipv4"`
	ServerIpv6    string `json:"server-ipv6"`
}

type GetStatusMessage struct {
	FeaturesStatistics bool `json:"features-statistics"`
}

func createMessage(key string, value interface{}) string {
	bytes, _ := json.Marshal(map[string]interface{}{key: value})
	return string(bytes)
}
