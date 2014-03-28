/**
 * \file
 * \author: tanb
 * Mon Feb 10 14:52:10 CST 2014
 * App-layer for DRDA protocol used in IBM DB2 C/S communication
 */

#include "app-layer-drda-common.h"
#include "app-layer-drda.h"
#include "stream.h"

static uint16_t DRDAProbingParser(uint8_t *in, uint32_t len,
        uint32_t *offset) {
    /* do nothing on @in checking */
	if (len == 0)
		return ALPROTO_UNKNOWN;
    return ALPROTO_DRDA;
}

void RegisterDRDAParsers(void) {
    char *proto_name = "drda";
	if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_DRDA, proto_name);
		if (RunmodeIsUnittests()) {
			AppLayerProtoDetectPPRegister(IPPROTO_TCP, "50000",
					ALPROTO_DRDA, 0, 0, STREAM_TOSERVER, DRDAProbingParser);
		} else {
			int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
					proto_name, ALPROTO_DRDA, 0, 0, DRDAProbingParser);
			if (!have_cfg) {
				SCLogWarning(SC_ERR_DRDA_CONFIG, "no DRDA config found, "
						"enabling DRDA detection on port 50000");
				AppLayerProtoDetectPPRegister(IPPROTO_TCP, "50000",
						ALPROTO_DRDA, 0, 0, STREAM_TOSERVER, DRDAProbingParser);
			}
		}
		AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_DRDA,
				STREAM_TOSERVER | STREAM_TOCLIENT);
	} else {
		SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
		return ;
	}

	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DRDA, STREAM_TOSERVER, DRDAParseClientRecord);
		AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DRDA, STREAM_TOCLIENT, NULL); /* do not parse server response */
		AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DRDA, DRDAStateAlloc, DRDAStateFree);
	}
	
#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_DRDA, DRDAParserRegisterTests);
#endif
    return;
}

#ifdef UNITTESTS
void DRDAParserRegisterTests(void) {
    /* TODO */
}
#endif
