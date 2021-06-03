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

type ErrorMessage struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type Features struct {
	fields map[string]interface{}
}

//goland:noinspection GoUnusedExportedFunction
func NewFeatures() *Features {
	result := new(Features)
	result.fields = map[string]interface{}{}
	return result
}

func (feat *Features) UnmarshalJSON(data []byte) error {
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	feat.fields = fields
	return nil
}

func (feat *Features) MarshalJSON() ([]byte, error) {
	return json.Marshal(feat.fields)
}

func (feat *Features) HasKey(name string) bool {
	_, ok := feat.fields[name]
	return ok
}

func (feat *Features) GetCount() int {
	return len(feat.fields)
}

func (feat *Features) GetKeys() *StringArray {
	result := make([]string, 0, len(feat.fields))
	for key := range feat.fields {
		result = append(result, key)
	}
	return &StringArray{values: result}
}

func (feat *Features) SetInt(name string, value int) {
	feat.fields[name] = float64(value)
}

func (feat *Features) GetInt(name string) int {
	return int(feat.fields[name].(float64))
}

func (feat *Features) SetString(name string, value string) {
	feat.fields[name] = value
}

func (feat *Features) GetString(name string) string {
	return feat.fields[name].(string)
}

func (feat *Features) SetBool(name string, value bool) {
	feat.fields[name] = value
}

func (feat *Features) GetBool(name string) bool {
	return feat.fields[name].(bool)
}

func (feat *Features) update(other *Features) {
	for k, v := range other.fields {
		feat.fields[k] = v
	}
}

func (feat *Features) diffTo(other *Features) *Features {
	result := NewFeatures()
	for k, v := range other.fields {
		if feat.fields[k] != v {
			result.fields[k] = v
		}
	}
	return result
}

type StatusMessage struct {
	State    string    `json:"state"`
	Features *Features `json:"features"`
	Reason   *Reason   `json:"reason"`
	SwitchTo string    `json:"please-switch-to"`
}

type Reason struct {
	Code        int    `json:"code"`
	Final       bool   `json:"final"`
	Description string `json:"description"`
}

type GetMessage struct{}

func createMessage(key string, value interface{}) string {
	bytes, _ := json.Marshal(map[string]interface{}{key: value})
	return string(bytes)
}
