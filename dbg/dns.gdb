file ./src/suricata

#b main
#b RegisterAllModules 
#b RegisterDNSTCPParsers
#b DNSTcpProbingParser
#b DNSTCPRequestParse
#b DNSTCPResponseParse
#b DNSStateFree
#b DNSStateAlloc
#b JsonDnsLogger
#b output-json-dns.c:LogQuery
b LogDnsLogger

b OutputTxLog if p->flow->alproto == 13

r -c yaml/dns.yaml -q 0
set print pretty
set logging on
#set scheduler-locking off

# use dig +tcp google.com to test DNS protocols
