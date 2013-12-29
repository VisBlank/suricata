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
#b StreamTcpReassembleHandleSegment
#
#
#b TmModuleDetectRegister
#b DetectThreadInit

# ----2013年 12月 28日 星期六 15:39:23 CST  ----------------
#b TmThreadsSlotVarRun
#b TmThreadsSlotProcessPkt
#b TmThreadsSlotPktAcqLoop
#-- various callback
#b ReceivePcapFileLoop
#b DecodePcap
#b PcapCallbackLoop
#b StreamTcp
b StreamTcpReassembleHandleSegment
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
b HTPHandleRequestData
b HTPHandleResponseData

#---------------------- debug mysql data -----------------------
b MySqlParseServerRecord
b MySqlParseClientRecord

r -c suricata.yaml -i wlan0
set print pretty
