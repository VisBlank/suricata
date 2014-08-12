/**
 * app layer for TNS protocol used in Oracle
 * author: tanb <tanb@titansec.com.cn>
 * date: Fri Apr  4 10:48:31 CST 2014
 */

#include "suricata-common.h"
#include "app-layer-oracle11g-common.h"
#include "app-layer-oracle.h"
#include "stream.h"

static uint16_t Oracle11gProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0) {
        return ALPROTO_UNKNOWN;
    }

    /* TODO: Check the Oracle header (8 Bytes) */
    return ALPROTO_ORACLE11G;
}

void RegisterOracle11gParsers(void) {
    char *proto_name = "oracle11g";
	if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_ORACLE11G, proto_name);
		if (RunmodeIsUnittests()) {
			AppLayerProtoDetectPPRegister(IPPROTO_TCP, "1521",
					ALPROTO_ORACLE11G, 0,
					ORACLE11G_HEADER_SIZE, /* FIXME */
					STREAM_TOSERVER, Oracle11gProbingParser);
		} else {
			int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
					proto_name, ALPROTO_ORACLE11G, 0,
					ORACLE11G_HEADER_SIZE, /* FIXME */
					Oracle11gProbingParser);
			if (!have_cfg) {
				return;
			}
		}
	} else {
		SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
		return;
	}

    if (AppLayerParserConfParserEnabled("oracle11g", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_ORACLE11G, STREAM_TOSERVER, Oracle11gParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_ORACLE11G, STREAM_TOCLIENT, Oracle11gParseServerRecord);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_ORACLE11G, Oracle11gStateAlloc, Oracle11gStateFree);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_ORACLE11G, Oracle11gGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_ORACLE11G, Oracle11gGetTxCnt);
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP,
                ALPROTO_ORACLE11G, Oracle11gGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_ORACLE11G, Oracle11gGetAlstateProgress);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP,  ALPROTO_Oracle11G, Oracle11gParserRegisterTests);
#endif
    return;
}

#ifdef UNITTESTS
void Oracle11gParserRegisterTests(void) {
    /* TODO */
}
#endif
