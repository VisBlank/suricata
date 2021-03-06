file ./src/suricata
#b main
#
#------------ oracle protocol ------------
#b RegisterTNS11gParsers
#b TNS11gProbingParser
#b TNS11gParseClientRecord
#b DecodeIPV4
b AppLayerParserParse
#b AppLayerHandleTCPData
#b FlowHandlePacket
#b AppLayerParserRegisterParser
#b StreamTcpReassembleInlineAppLayer
#--------------------
#b RegisterMySqlParsers

b MySqlParseServerRecord
#b RegisterMysqlParsers
#b MysqlParseServerRecord
b MysqlParseClientRecord
#b DetectFlowMatch 
#--------------------
#b DecodeEnthernet
#b DecodeIPV4
#b DecodeTCP
#b AppLayerParse
#b AppLayerHandleTCPData 
#--------------------
#b TmqhInputPacketpool
#b TmModuleDetectRegister
#b DetectThreadInit

# ---- main break point  ----------------
#b TmThreadsSlotVarRun

#b ./src/tm-threads.c:556
#b tm-threads.c:556
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
#b DecodePcap
#b PcapCallbackLoop
#b StreamTcp if p->src->family==2
#b StreamTcpReassembleHandleSegment
#b StreamTcpPacket
#b ./src/stream-tcp.c:4210
#b decode.c:214
#    commands
#    silent
#
#    if p->ext_pkt != 0
#        x/80xb p->ext_pkt
#    else
#        cont
#    end
#    end

#b stream-tcp.c:4210
#    commands
#    silent
#    #set $src_addr = (char *)inet_ntoa(p->src.address.address_un_data32[0])
#    #set $dst_addr = (char *)inet_ntoa(p->dst.address.address_un_data32[0])
#    #printf "ssn:0x%x, family:%d,src_addr: %s:%d, dst_addr: %s:%d\n", ssn, p->src.family, $src_addr, p->sp , $dst_addr, p->dp
#    if ssn != 0
#        if p->dp == 3306
#            set $src_addr = (p->src.address.address_un_data32[0])
#            set $dst_addr = (p->dst.address.address_un_data32[0])
#            printf "ssn->state:%d, family:%d,src_addr: %d:%d, dst_addr: %d:%d\n", ssn->state, p->src.family, $src_addr, p->sp , $dst_addr, p->dp
#
#            if p->ext_pkt != 0
#                x/80xb p->ext_pkt
#            end
#        end
#        #cont
#    else
#        cont
#    end
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
#b MysqlParseServerRecord
#b MysqlParseClientRecord
#b MysqlProbingParser
#b AppLayerDetectGetProto
#b RegisterMysqlParsers
#b ParseMysqlPktHdr
#b loadLogConf
#b MysqlGetEventInfo
#b DetectAppLayerEventParseApp
#b RegisterAppLayerParsers
 
#---------------------- debug mysql log -----------------------
#b TmModuleLogMysqlRegister
#b RunModeInitializeOutputs
#b LogMysqlLogThreadInit
#b log-mysqllog.c:166
#    commands
#    silent
#    print s
#    cont
#    end
#b MysqlTransactionFree
#b MysqlStateFree

# --------------------- all log debug -----------------------
#b AlertFastLog
#b AlertDebugLog
#b AlertPrelude
#b AlertSyslog
#b Unified2Alert
#
#--------------------- unitest ----------------------------
#b MysqlParserRegisterTests
#b AppLayerRegisterProbingParser
#b InitPendingPkt
#b ParseClientCmd
#b MysqlStateFree
#b MysqlTransactionFree
#b MysqlParserTest04
