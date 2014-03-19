/**
 * \file
 * \author
 * Mon Jan 20 13:53:14 CST 2014
 * App-layer for TDS protocols
 */

#include "suricata-common.h"
#include "app-layer-tds-common.h"
#include "app-layer-tds.h"

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
    if (AppLayerProtoDetectionEnabled(proto_name)) {
        if (RunmodeIsUnittests()) {
            AppLayerRegisterProbingParser(&alp_proto_ctx,
                    IPPROTO_TCP, "1433", proto_name,
                    ALPROTO_TDS, 0, sizeof(TDSPktHeader),
                    STREAM_TOSERVER, TDSProbingParser);
        } else {
            AppLayerParseProbingParserPorts(proto_name, ALPROTO_TDS, 0,
                    sizeof(TDSPktHeader), TDSProbingParser);
        }

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_TDS, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name, ALPROTO_TDS, STREAM_TOSERVER, TDSParseClientRecord);
        AppLayerRegisterProto(proto_name, ALPROTO_TDS, STREAM_TOCLIENT, TDSParseServerRecord);
        AppLayerRegisterStateFuncs(ALPROTO_TDS, TDSStateAlloc, TDSStateFree);
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
