## pcap thread
    TmThreadsSlotPktAcqLoop -> ReceivePcapLoop ->
    PcapCallbackLoop -> TmThreadsSlotProcessPkt ->
    TmThreadsSlotVarRun -> DecodePcap -> DecodeEthernet ->
    DecodeIPV4 ->

    ...

    [StreamTcpReassembleInlineAppLayer |StreamTcpReassembleAppLayer] -> AppLayerHandleTCPData -> AppLayerParse ->
    AppLayerDoParse -> al_parser_table[parser_idx].AppLayerParser()

    StreamTcpReassembleHandleSegment -> StreamTcpReassembleInlineAppLayer


## detect thread

    TmThreadSetSlots -> TmThreadsSlotVar(810) -> TmqhInputFlow -> SCCondWait(trans_q[tv->inq->id]);

    DetectEngineSpawnLiveRuleSwapMgmtThread -> DetectEngineLiveRuleSwap -> SCCondSignal(trans_q[tv->inq->id])
