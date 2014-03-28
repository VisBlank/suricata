/**
 * \file
 * \auth
 * app layer for TNS protocol used in Oracle
 */

#include "suricata-common.h"
#include "app-layer-tns11g-common.h"
#include "app-layer-tns.h"

static uint16_t TNSProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0) {
        return ALPROTO_UNKNOWN;
    }

    return ALPROTO_TDS;
}

void RegisterTNS11gParsers(void) {
#if 0
    char *proto_name = "tns";
    if (AppLayerProtoDetectionEnabled(proto_name)) {
        if (RunmodeIsUnittests()) {
            AppLayerRegisterProbingParser(&alp_proto_ctx,
                    IPPROTO_TCP, "1433", proto_name,
                    ALPROTO_TNS, 0, sizeof(TNSPktHeader),
                    STREAM_TOSERVER, TNSProbingParser);
        } else {
            AppLayerParseProbingParserPorts(proto_name, ALPROTO_TNS, 0,
                    sizeof(TNSPktHeader), TNSProbingParser);
        }

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_TNS,
                STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name, ALPROTO_TNS, STREAM_TOSERVER, TNSParseClientRecord);
        AppLayerRegisterProto(proto_name, ALPROTO_TNS, STREAM_TOCLIENT, TNSParseServerRecord);
        AppLayerRegisterStateFuncs(ALPROTO_TDS, TNSStateAlloc, TNSStateFree);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_TNS, TNSParserRegisterTests);
#endif
#endif
    return;
}

#ifdef UNITTESTS
void TNSParserRegisterTests(void) {
    /* TODO */
}
#endif
