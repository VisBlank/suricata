file ./src/suricata
b main

#--------------------
#b RegisterMySqlParsers
#b MySqlParseServerRecord
#b RegisterSSHParsers
#b SSHParseServerRecord
#b SSHParseClientRecord
#b DetectFlowMatch 
#--------------------
#b DecodeEnthernet
#b DecodeIPV4
#b DecodeTCP
#b AppLayerParse
#b AppLayerHandleTCPData 
#--------------------
#b   TmqhInputPacketpool
#b TmModuleDetectRegister
#b DetectThreadInit

# ---- main break point  ----------------
#b TmThreadsSlotVarRun

#b src/tm-threads.c:556
#   commands
#   silent
#   print SlotFunc
#   cont
#   end
#b TmThreadsSlotProcessPkt
#b TmThreadsSlotPktAcqLoop
#-- various callback
#b ReceivePcapFileLoop
#b DecodePcap if p->src->family==2
#b PcapCallbackLoop
#b StreamTcp if p->src->family==2
#b StreamTcpReassembleHandleSegment
#b StreamTcpPacket
#b src/stream-tcp.c:4210
#    commands
#    silent
#    print ssn
#    cont
#    end
#b StreamTcpPacketStateNone
#b Detect
#b RespondRejectFunc
#b AlertFastLog
#b AlertFastLogIPv4
#b AlertFastLogIPv6
#b AlertDebugLog
#b AlertPrelude
#b Unified2Alert
#b AlertPcapInfo
#b LogDropLog
#b LogHttpLog
#b LogHttpLogIPv4
#b LogHttpLogIPv6
#b LogTlsLog
#b LogTlsLogIPv4
#b LogTlsLogIPv6
#b PcapLog
#b LogFileLog
#b LogFilestoreLog
#b LogDnsLog
#r -c suricata.yaml -i eth0
#---------------------- debug http data -----------------------
#b HTPHandleRequestData
#b HTPHandleResponseData

#---------------------- debug mysql data -----------------------
#b src/app-layer-detect-proto.c:567
#   commands
#   silent
#   printf "ipproto: %d", ipproto
#   print pp_port
#   cont
#   end

b MysqlParseServerRecord
b MysqlParseClientRecord
b MysqlProbingParser
#b AppLayerDetectGetProto
b RegisterMysqlParsers
#b RegisterAppLayerParsers
 
#---------------------- debug mysql log -----------------------
#b TmModuleLogMysqlRegister
#b RunModeInitializeOutputs
#b LogMysqlLogThreadInit
#b LogMysqlLog

# --------------------- all log debug -----------------------
#b AlertFastLog
#b AlertDebugLog
#b AlertPrelude
#b AlertSyslog
#b Unified2Alert

r -c suricata.yaml -i wlan0
#r -c suricata.yaml -i eth0
set print pretty
#set print thread-events off
#set scheduler-locking on
