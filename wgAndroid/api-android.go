/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// #include "jni_go.h"
import "C"

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type AndroidLogger struct {
	level C.int
	tag   *C.char
}

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	C.__android_log_write(l.level, l.tag, cstring(fmt.Sprintf(format, args...)))
}

type TunnelHandle struct {
	manager *device.WireGuardStateManager
	device  *device.Device
	uapi    net.Listener
}

var tunnelHandles map[int32]TunnelHandle
var tunnelHandlesMutex sync.Mutex

func init() {
	tunnelHandles = make(map[int32]TunnelHandle)
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				if n == len(buf) {
					n--
				}
				buf[n] = 0
				C.__android_log_write(C.ANDROID_LOG_ERROR, cstring("WireGuard/GoBackend/Stacktrace"), (*C.char)(unsafe.Pointer(&buf[0])))
			}
		}
	}()
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string, socketType string, allowedSrcAddresses string) int32 {
	tag := cstring("WireGuard/GoBackend/" + interfaceName)
	connLogger := conn.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}
	logger := &device.Logger{connLogger}

	tun, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	protectSocket := func(fd int) int {
		return int(C.protectSocket(C.int(fd)))
	}

	logger.Verbosef("Attaching to interface %v", name)
	manager := device.NewWireGuardStateManager(logger, socketType == "udp")
	device := device.NewDevice(tun, conn.CreateStdNetBind(socketType, &connLogger, manager.SocketErrChan, protectSocket),
		logger, manager.HandshakeStateChan, allowedSrcAddresses)

	err = device.IpcSet(settings)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("IpcSet: %v", err)
		return -1
	}
	device.DisableSomeRoamingForBrokenMobileSemantics()

	var uapi net.Listener

	uapiFile, err := ipc.UAPIOpen(name)
	if err != nil {
		logger.Errorf("UAPIOpen: %v", err)
	} else {
		uapi, err = ipc.UAPIListen(name, uapiFile)
		if err != nil {
			uapiFile.Close()
			logger.Errorf("UAPIListen: %v", err)
		} else {
			go func() {
				for {
					conn, err := uapi.Accept()
					if err != nil {
						return
					}
					go device.IpcHandle(conn)
				}
			}()
		}
	}

	tunnelHandlesMutex.Lock()
	defer tunnelHandlesMutex.Unlock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		logger.Errorf("Unable to find empty handle")
		uapiFile.Close()
		device.Close()
		return -1
	}
	manager.Start(device)
	tunnelHandles[i] = TunnelHandle{device: device, uapi: uapi, manager: manager}
	return i
}

func getAndDeleteHandle(tunnelHandle int32) (TunnelHandle, bool) {
	tunnelHandlesMutex.Lock()
	defer tunnelHandlesMutex.Unlock()
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return TunnelHandle{}, ok
	}
	delete(tunnelHandles, tunnelHandle)
	return handle, ok
}

func getTunnelHandleWithLock(tunnelHandle int32) (TunnelHandle, bool) {
	tunnelHandlesMutex.Lock()
	defer tunnelHandlesMutex.Unlock()
	handle, ok := tunnelHandles[tunnelHandle]
	return handle, ok
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	handle, ok := getAndDeleteHandle(tunnelHandle)
	if !ok {
		return
	}
	
	if handle.uapi != nil {
		handle.uapi.Close()
	}
	handle.device.Close()
	handle.manager.Close()
}

//export wgSetNetworkAvailable
func wgSetNetworkAvailable(tunnelHandle int32, available int) int {
	handle, ok := getTunnelHandleWithLock(tunnelHandle)
	if !ok {
		return -1
	}
	handle.manager.SetNetworkAvailable(available != 0)
	return 0
}

//export wgGetState
func wgGetState(tunnelHandle int32) int {
	handle, ok := getTunnelHandleWithLock(tunnelHandle)
	if !ok {
		return -1
	}
	return int(handle.manager.GetState())
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
	handle, ok := getTunnelHandleWithLock(tunnelHandle)
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
	handle, ok := getTunnelHandleWithLock(tunnelHandle)
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	handle, ok := getTunnelHandleWithLock(tunnelHandle)
	if !ok {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
