/**
 * \file
 * \author: tanb
 * Mon Feb 10 14:52:10 CST 2014
 * App-layer for DRDA protocol used in IBM DB2 C/S communication
 */

#include "app-layer-drda-common.h"
#include "app-layer-drda.h"

static uint16_t DRDAProbingParser(uint8_t *in, uint32_t len,
        uint32_t *offset) {
    /* do nothing on @in checking */
    (void)in;
    (void)len;
    (void)offset;
    return ALPROTO_DRDA;
}

void RegisterDRDAParsers(void) {
#if 0
    char *proto_name = "drda";
    static const int drda_hdr_len = 0; /* FIXME */
    if (AppLayerProtoDetectionEnabled(proto_name)) {
        if (RunmodeIsUnittests()) {
            AppLayerRegisterProbingParser(&alp_proto_ctx,
                    IPPROTO_TCP, "50000", proto_name,
                    ALPROTO_DRDA, 0, drda_hdr_len,
                    STREAM_TOSERVER, DRDAProbingParser);
        } else {
            AppLayerRegisterParserAcceptableDataDirection(ALPROTO_DRDA,
                    STREAM_TOSERVER | STREAM_TOCLIENT);
        } else {
            SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
            return;
        }
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name,
                ALPROTO_DRDA, STREAM_TOSERVER, DRDAParseClientRecord);
        AppLayerRegisterProto(proto_name,
                ALPROTO_DRDA, STREAM_TOCLIENT, DRDAParseServerRecord);
        AppLayerRegisterStateFuncs(ALPROTO_DRDA,
                DRDAStateAlloc, DRDAStateFree);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_DRDA, DRDAParserRegisterTests);
#endif
#endif
    return;
}

#ifdef UNITTESTS
void DRDAParserRegisterTests(void) {
    /* TODO */
}
#endif
