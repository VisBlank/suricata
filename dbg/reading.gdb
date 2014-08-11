file ./src/suricata

b main
#b RunModeSetIPSAutoFp
#b AppLayerSetup
#b FlowInitConfig
#b TmThreadsSlotPktAcqLoop
#b ReceiveNFQLoop
#b NFQCallBack
#b NFQRecvPkt
#b DecodeNFQ
#b DecodeIPV4
#b ReceiveNFQThreadInit
#b NFQInitThread
#b NFQRegisterQueue
#b TmThreadsSlotVarRun
#b TmThreadsSlotVar
#b StreamTcp

r -c yaml/mysql.yaml -q 0
#r -c yaml/mysql.yaml -i wlan0
set print pretty
set logging on
set scheduler-locking off
