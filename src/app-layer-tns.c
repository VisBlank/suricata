/**
 * \file
 * \auth
 * app layer for TNS protocol used in Oracle
 */

#include "suricata-common.h"
#include "app-layer-tns11g-common.h"
#include "app-layer-tns.h"
#include "stream.h"

#define TNS11G_HEADER_SIZE 8

static uint16_t TNS11gProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0) {
        return ALPROTO_UNKNOWN;
    }

    return ALPROTO_TDS;
}

void RegisterTNS11gParsers(void) {
    char *proto_name = "tns11g";
	if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_TNS11G, proto_name);
		if (RunmodeIsUnittests()) {
			AppLayerProtoDetectPPRegister(IPPROTO_TCP, "1521",
					ALPROTO_TNS11G, 0,
					TNS11G_HEADER_SIZE, /* FIXME */
					STREAM_TOSERVER, TNS11gProbingParser);
		} else {
			int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
					proto_name, ALPROTO_TNS11G, 0,
					TNS11G_HEADER_SIZE, /* FIXME */
					TNS11gProbingParser);
			if (!have_cfg) {
				return;
#if 0
				SCLogWarning(SC_ERR_MYSQL_CONFIG, "no TNS11g config found, "
						 "enabling TNS11g detection on port 1521");
				AppLayerProtoDetectPPRegister(IPPROTO_TCP, "1521",
						ALPROTO_TNS11G, 0,
						0, /* FIXME */
						STREAM_TOSERVER, TNS11gProbingParser);
#endif
			}
		}

		AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TNS11G,
				STREAM_TOSERVER | STREAM_TOCLIENT);
	} else {
		SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
		return;
	}

    if (AppLayerParserConfParserEnabled("tns11g", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TNS11G, STREAM_TOSERVER, TNS11gParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TNS11G, STREAM_TOCLIENT, TNS11gParseServerRecord);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TNS11G, TNS11gStateAlloc, TNS11gStateFree);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP,  ALPROTO_TNS11G, TNS11gParserRegisterTests);
#endif
    return;
}

#ifdef UNITTESTS
void TNS11gParserRegisterTests(void) {
    /* TODO */
}
#endif
