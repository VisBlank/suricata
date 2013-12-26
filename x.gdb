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


b TmModuleDetectRegister
b Detect
b DetectThreadInit
r -c suricata.yaml -i eth0
set print pretty
