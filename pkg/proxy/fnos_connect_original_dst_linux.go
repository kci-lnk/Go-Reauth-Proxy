//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ip6tSoOriginalDst = 80

func fnosConnectOriginalDestinationPort(conn net.Conn) (int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("FN Connect connection type %T is not TCP", conn)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("access FN Connect socket: %w", err)
	}

	local, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP == nil {
		return 0, errors.New("FN Connect local TCP address is unavailable")
	}

	var port int
	var socketErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		if local.IP.To4() != nil {
			var address unix.RawSockaddrInet4
			size := uint32(unsafe.Sizeof(address))
			_, _, errno := unix.Syscall6(
				unix.SYS_GETSOCKOPT,
				fd,
				uintptr(unix.SOL_IP),
				uintptr(unix.SO_ORIGINAL_DST),
				uintptr(unsafe.Pointer(&address)),
				uintptr(unsafe.Pointer(&size)),
				0,
			)
			if errno != 0 {
				socketErr = errno
				return
			}
			port = networkPort(address.Port)
			return
		}

		var address unix.RawSockaddrInet6
		size := uint32(unsafe.Sizeof(address))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IPV6),
			uintptr(ip6tSoOriginalDst),
			uintptr(unsafe.Pointer(&address)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			socketErr = errno
			return
		}
		port = networkPort(address.Port)
	})
	if controlErr != nil {
		return 0, fmt.Errorf("inspect FN Connect socket: %w", controlErr)
	}
	if socketErr != nil {
		return 0, fmt.Errorf("read FN Connect original destination: %w", socketErr)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("FN Connect original destination port %d is invalid", port)
	}
	return port, nil
}

func networkPort(value uint16) int {
	bytes := (*[2]byte)(unsafe.Pointer(&value))
	return int(bytes[0])<<8 | int(bytes[1])
}
