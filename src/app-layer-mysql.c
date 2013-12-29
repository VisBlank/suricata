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

#if 0
static int MySqlDecode(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t ilen)
{
    return 0; /* TODO */
}

static int MySqlParseClientVersion(Flow *f, void *mysql_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output)
{
    /* TODO: */
    return 0;
}
#endif

static int MySqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    MySqlState *state = (MySqlState *)alstate;
    SCEnter();

    int ret = 0;

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            alstate, pstate, input, input_len);
    if (pstate == NULL)
        SCReturnInt(-1);

    state->direction = MYSQL_DIRECTION_TO_CLIENT;
#if 0
    if (!(state->flags & MYSQL_FLAGS_CLIENT_VERSION_PARSED)) {
        ret = MySqlParseClientVersion(f, ssh_state, pstate, input, input_len, output);
        if (ret < 0) {
            SCLogDebug("Invalid MySql client version string");
            SCReturnInt(-1);
        } else if (state->flags & MYSQL_FLAGS_CLIENT_VERSION_PARSED) {
            SCLogDebug("MySql client version string parsed");
            input += input_len - ret;
            input_len -= (input_len - ret);
            pstate->parse_field = 1;
            ret = 1;
            if (input_len == 0)
                SCReturnInt(ret);
        } else  {
            SCLogDebug("MySql client version not parsed yet");
            pstate->parse_field = 0;
            SCReturnInt(ret);
        }
    } else {
        SCLogDebug("MySql client version already parsed");
    }
#endif
    /* TODO */
    return 0;
}

static int MySqlParseServerRecord(Flow *f, void *mysql_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output)
{
    MySqlState *state = (MySqlState *)mysql_state;
    SCEnter();

    int ret = 0;

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            mysql_state, pstate, input, input_len);
    if (pstate == NULL)
        SCReturnInt(-1);
    
    state->direction = MYSQL_DIRECTION_TO_SERVER;

    /* TODO */
    return 0;
}

void RegisterMySqlParsers(void) {
    char *proto_name = "mysql";

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        /* TODO:
         * MySql protocol got no prefix in the protocol, so we capture every packages pass by 
         */
        //AlpProtoAddCI(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_MYSQL, "||", 1, 0, STREAM_TOSERVER);

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_MYSQL, STREAM_TOSERVER | STREAM_TOCLIENT);
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
