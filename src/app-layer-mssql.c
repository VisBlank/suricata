/*
 * parser for MSSQL(TDS) protocol
 * author: coanor <coanor@gmail.com>
 * daate: Tue Jun 10 09:37:17 CST 2014
 */

#include "suricata-common.h"
#include "app-layer-mssql-common.h"
#include "app-layer-mssql.h"
#include "stream.h"

static uint16_t MSSqlProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0 || ilen < sizeof(TDSHeader)) {
        return ALPROTO_UNKNOWN;
    }

    if (TDSRequestParse(input, ilen) == -1) {
        return ALPROTO_FAILED;
    }

    return ALPROTO_MSSQL;
}

void RegisterMSSqlParsers(void) {
    char *proto_name = "mssql";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_MSSQL, proto_name);
        if (RunmodeIsUnittests()) {
			AppLayerProtoDetectPPRegister(
                    IPPROTO_TCP, "1443", ALPROTO_MSSQL, 0,
					sizeof(TDSHeader),
                    STREAM_TOSERVER, MSSqlProbingParser);
        } else {
			int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
					proto_name, ALPROTO_MSSQL, 0, sizeof(TDSHeader), MSSqlProbingParser);

			/* if not configured, enable the default 3306 port */
			if (!have_cfg) {
				return;
			}
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MSSQL, STREAM_TOSERVER, TDSParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MSSQL, STREAM_TOCLIENT, TDSParseServerRecord);
		AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MSSQL, TDSStateAlloc, TDSStateFree);

        /* TODO: should we add get/has event callbacks? */

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MSSQL, TDSGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MSSQL, TDSGetTxCnt);
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP,
                ALPROTO_MSSQL, TDSGetAlstateProgressCompletionStatus);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_MSSQL, TDSGetAlstateProgress);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MSSQL, TDSParserRegisterTests);
#endif

    return;
}

void TDSParserRegisterTests(void) {
    /* TODO */
}
