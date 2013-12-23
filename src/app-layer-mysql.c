/**
 * \file
 * \author
 *
 * App-layer parser for MySql protocol
 *
 */

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "app-layer-mysql.h"

static int MySqlDecode(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t ilen) {
    return 0; /* TODO */
}

static int MySqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    return MySqlDecode(f, 0 /* to server */, alstate, pstate, input, input_len);
}

static int MySqlParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    return MySqlDecode(f, 1 /* to client */, alstate, pstate, input, input_len);
}

void RegisterMySqlParsers(void) {
    char *proto_name = "mysql";

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        /* TODO: */
        AlpProtoAddCI(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_MYSQL, "||", 1, 0, STREAM_TOSERVER);

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_MYSQL, STREAM_TOSERVER);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOSERVER, MySqlParseClientRecord);
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOCLIENT, MySqlParseServerRecord);
    }

    return;
}
