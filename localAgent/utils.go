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
	"crypto/x509"
	"strings"
	"time"
)

type ErrorType = int

const (
	ErrorClientCertExpired ErrorType = iota
	ErrorClientCertUnknownCA
	ErrorInvalidServerCert
	ErrorUnreachable
	ErrorOther
)

func translateError(err error) ErrorType {
	switch err.(type) {
	case
		*x509.CertificateInvalidError, x509.CertificateInvalidError,
		*x509.HostnameError, x509.HostnameError,
		*x509.UnknownAuthorityError, x509.UnknownAuthorityError:
		return ErrorInvalidServerCert
	default:
		errString := err.Error()
		if strings.Contains(errString, "expired certificate") {
			return ErrorClientCertExpired
		} else if strings.Contains(errString, "unknown certificate authority") {
			return ErrorClientCertUnknownCA
		} else if strings.Contains(errString, "connection refused") ||
			strings.Contains(errString, "timed out") ||
			strings.Contains(errString, "timeout") {
			return ErrorUnreachable
		}
	}
	return ErrorOther
}

// StringArray - helper struct introduced because gomobile doesn't support array return types
type StringArray struct {
	values []string
}

func (arr *StringArray) GetCount() int {
	return len(arr.values)
}

func (arr *StringArray) Get(i int) string {
	return arr.values[i]
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func multiplyDuration(a time.Duration, b float64) time.Duration {
	return time.Duration(b*float64(a.Nanoseconds())) * time.Nanosecond
}
