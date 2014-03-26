/**
 * \file
 * \author
 * Mon Jan 20 13:53:14 CST 2014
 * App-layer for TDS protocols
 */

#include "suricata-common.h"
#include "app-layer-tds-common.h"
#include "app-layer-tds.h"
#include "stream.h"

static uint16_t TDSProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0 || ilen < sizeof(TDSPktHeader)) {
        return ALPROTO_UNKNOWN;
    }

    if (TDSRequestParse(input, ilen) == -1) {
        return ALPROTO_FAILED;
    }

    return ALPROTO_TDS;
}

void RegisterTDSParsers(void) {
    char *proto_name = "tds";
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_TDS, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "1433",
					ALPROTO_TDS, 0, sizeof(TDSPktHeader),
                    STREAM_TOSERVER, TDSProbingParser);
        } else {
			int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
					proto_name, ALPROTO_TDS, 0, sizeof(TDSPktHeader), TDSProbingParser);
			if (!have_cfg) {
				SCLogWarning(SC_ERR_TDS_CONFIG, "no TDS(MSSQL) config found, "
						"enabling TDS detection on port 1433");
				AppLayerProtoDetectPPRegister(IPPROTO_TCP, "1433", ALPROTO_TDS, 0,
						sizeof(TDSPktHeader), STREAM_TOSERVER, TDSProbingParser);
			}
        }

		AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TDS,
				STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TDS, STREAM_TOSERVER, TDSParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TDS, STREAM_TOCLIENT, TDSParseServerRecord);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TDS, TDSStateAlloc, TDSStateFree);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_TDS, TDSParserRegisterTests);
#endif
    return;
}

#ifdef UNITTESTS
void TDSParserRegisterTests(void) {
    /* TODO */
}
#endif
