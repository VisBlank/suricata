file ./src/suricata
b main
#b RegisterMySqlParsers
#b MySqlParseServerRecord
#b RegisterSSHParsers
#b SSHParseServerRecord
#b SSHParseClientRecord
#b DetectFlowMatch 
b DecodeIPV4
b AppLayerParse
b AppLayerHandleTCPData 
r -c suricata.yaml -i eth0
set print pretty
