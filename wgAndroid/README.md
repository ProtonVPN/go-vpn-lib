# Interface between WireGuard Go and WireGuard Android

This code replaces (and is almost identical to)
wireguard-android/tools/tunnel/libwg-go for use with gomobile builds of
wireguard-go.

Files:
- api-android.go - equivalent of libwg-go/api-android.go
- goruntime-boottime-overmonitonic.diff - patch to change clock in Go runtime
  module. It needs to be applied before building this module.

They should be kept up-to-date to match the originals in wireguard-android.
