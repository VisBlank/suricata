file ./src/suricata

#b main
#b RegisterOracle11gParsers
#b Oracle11gParseClientRecord
#b Oracle11gParseServerRecord
#b Oracle11gParseData
#b app-layer-oracle11g-common.c:291
#
#b AppLayerParserParse if alproto==14
#b AppLayerHandleTCPData
#b app-layer.c:163 if *alproto==14
#b StreamTcpReassembleInlineAppLayer
#
#b source-nfq.c:910 if rv > 139 && tv->data[138]==0x03 && tv->data[139] == 0x5e
#b FlowSetSessionNoApplayerInspectionFlag
#b StreamTcpReassembleInlineAppLayer
#b AppLayerParserParse
#b stream-tcp.c:581
#b StreamTcpInitConfig
#b stream-tcp-reassemble.c:2110 if p->flow->flags & FLOW_NO_APPLAYER_INSPECTION
#	command
#	silent
#	print seg->payload
#	x/100cb seg->payload
#	cont
#	end
#b TmThreadsSlotProcessPkt
#b TmThreadsSlotVarRun
#b DecodeIPV4
#b StreamTcp
#b StreamTcpPacketStateEstablished
#b HandleEstablishedPacketToServer
#b StreamTcpReassembleHandleSegment
#b FlowGetFlowFromHash

#b Oracle11gProbingParser

#b NFQRecvPkt
#b NFQInitThread

#b CaptrueSQL
#b Oracle11gParseData
#b Oracle11gStateFree
#b Oracle11gStateAlloc
#b FlowCleanupAppLayer

b JsonOracle11gLogger
b Oracle11gGetAlstateProgress
###################################
# debug flow manager thread
###################################
#awatch p->flow->flags
#awatch flow_hash
#b FlowManagerThread

r -c yaml/oracle.yaml -q 0
set print pretty
