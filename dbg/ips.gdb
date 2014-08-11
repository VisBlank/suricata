file ./src/suricata

b AppLayerParserParse
b AppLayerHandleTCPData
b StreamTcpReassembleInlineAppLayer

r -c suricata.yaml -q 0
set print pretty
#set scheduler-locking on
