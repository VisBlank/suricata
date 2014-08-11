#b TmModuleLogTDSRegister
#b RunModeInitializeOutputs
#b LogTDSLogThreadInit
#b TDSParseClientRecord
#b TDSParseServerRecord
#b log-tdslog.c:226
#b app-layer-tds-common.c:61

#r -c suricata.yaml -i wlan0
#r -c suricata.yaml -i eth0
r -c suricata.yaml -q 0
#r -u -U mysql --fatal-unittests 
set print pretty
#set pagination no
#set print thread-events off
#set scheduler-locking on
