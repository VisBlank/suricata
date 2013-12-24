TmThreadsSlotPktAcqLoop -> ReceivePcapLoop ->
PcapCallbackLoop -> TmThreadsSlotProcessPkt ->
TmThreadsSlotVarRun -> DecodePcap -> DecodeEthernet ->
DecodeIPV4 -> AppLayerHandleTCPData -> AppLayerParse ->
AppLayerDoParse -> al_parser_table[parser_idx].AppLayerParser()
