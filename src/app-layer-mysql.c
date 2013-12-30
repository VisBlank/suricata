/**
 * \file
 * \author
 *
 * App-layer parser for Mysql protocol
 *
 */

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "app-layer-mysql.h"
#include "util-byte.h"

typedef enum {
	MYSQL_COMMAND_SLEEP               = 0x00,
	MYSQL_COMMAND_QUIT                = 0x01,
	MYSQL_COMMAND_INIT_DB             = 0x02,
	MYSQL_COMMAND_QUERY               = 0x03,
	MYSQL_COMMAND_FIELD_LIST          = 0x04,
	MYSQL_COMMAND_CREATE_DB           = 0x05,
	MYSQL_COMMAND_DROP_DB             = 0x06,
	MYSQL_COMMAND_REFRESH             = 0x07,
	MYSQL_COMMAND_SHUTDOWN            = 0x08,
	MYSQL_COMMAND_STATISTICS          = 0x09,
	MYSQL_COMMAND_PROCESS_INFO        = 0x0a,
	MYSQL_COMMAND_CONNECT             = 0x0b,
	MYSQL_COMMAND_PROCESS_KILL        = 0x0c,
	MYSQL_COMMAND_DEBUG               = 0x0d,
	MYSQL_COMMAND_PING                = 0x0e,
	MYSQL_COMMAND_TIME                = 0x0f,
	MYSQL_COMMAND_DELAYED_INSERT      = 0x10,
	MYSQL_COMMAND_CHANGE_USER         = 0x11,
	MYSQL_COMMAND_BINLOG_DUMP         = 0x12,
	MYSQL_COMMAND_TABLE_DUMP          = 0x13,
	MYSQL_COMMAND_CONNECT_OUT         = 0x14,
	MYSQL_COMMAND_REGISTER_SLAVE      = 0x15,
	MYSQL_COMMAND_STMT_PREPARE        = 0x16,
	MYSQL_COMMAND_STMT_EXECUTE        = 0x17,
	MYSQL_COMMAND_STMT_SEND_LONG_DATA = 0x18,
	MYSQL_COMMAND_STMT_CLOSE          = 0x19,
	MYSQL_COMMAND_STMT_RESET          = 0x1a,
	MYSQL_COMMAND_SET_OPTION          = 0x1b,
	MYSQL_COMMAND_STMT_FETCH          = 0x1c,
	MYSQL_COMMAND_DAEMON              = 0x1d,
	MYSQL_COMMAND_BINLOG_DUMP_GTID    = 0x1e,
	MYSQL_COMMAND_RESET_CONNECTION    = 0x1f,
} MysqlRequestCommand;

typedef struct MysqlClient_ {
    char *username;
    int address;
    /* more to add */
} MysqlClient;

typedef struct MysqlState_ {
    uint8_t flags;
    MysqlClient cli;

    /* TODO: add more */
} MysqlState;


/* directions */
#define MYSQL_DIRECTION_TO_SERVER 0x00
#define MYSQL_DIRECTION_TO_CLIENT 0x01

/* status */
#define MYSQL_STATE_INITIAL          0x00
#define MYSQL_STATE_SERVER_HANDSHAKE 0x01
#define MYSQL_STATE_CLIENT_AUTH      0x02
#define MYSQL_STATE_SERVER_AUTH_RESP   0x04
#define MYSQL_STATE_CLIENT_COMMAND   0x08
#define MYSQL_STATE_SERVER_RESPONSE  0x10

typedef struct MysqlPktHeader_ {
    int payload_len:3;
    int sequence_id:1;
} MysqlPktHeader;

typedef struct MysqlServerHandshake_{
    MysqlPktHeader hdr;
    char reserved_0;
    char reserved_1;
    char reserved_10[10]; /* reserved 10 bytes */
    char crypt_part2[12];
    int conn_id;
    char crypt_part1[8];
    short server_attr_l; /* low 2 bytes */
    short server_attr_h; /* high 2 bytes */
    short server_state;
    char *client_version; /* dynamic length */
} MysqlServerHandshake;

typedef struct MysqlClientAuth_ {
    MysqlPktHeader hdr;
    int client_available_attr;
    int max_pkt_len;
    char charset;
    char reserved[23];
    char *username;
    char password_len;
    char *password;
    char *initial_db_name;
} MysqlClientAuth;

typedef struct MysqlServerAuthResponse_ { 
    MysqlPktHeader hdr;
    char status;
    char affected_rows[9]; /* lenenc_int, maybe 1,3,4,9 bytes */
    char last_insert_id[9]; /* lenenc_int, maybe 1,3,4,9 bytes */
    short warnings;
    char *msg;
} MysqlServerAuthResponse;

typedef struct MysqlClientCommand_ {
    MysqlPktHeader hdr;
    char cmd;
    char *sql;
} MysqlClientCommand;

/* not use */
typedef struct MysqlResponse_ {
    MysqlPktHeader hdr;
    /* TODO */
} MysqlResponse;

/* ================================================================== */

int parseMysqlPktHdr(MysqlPktHeader *hdr, uint8_t *input) {
    int ret;
    uint32_t res;

    if ((ret = ByteExtractUint32(&res, BYTE_BIG_ENDIAN, 3, input)) != 0) {
        return -1;
    }
    
    hdr->payload_len = res;
    hdr->sequence_id = input[3];
    return 0;
}

void logUserLoginHist(MysqlState *s, MysqlClientAuth *ca) {
    /* TODO */
}

void logLoginResp(MysqlState *s, MysqlServerAuthResponse *ar) {
    /* TODO */
}

void logQueryHist(MysqlState *s, MysqlClientCommand *cmd) {
    /* TODO */
}

static int parseServerHs(MysqlState *s, uint8_t *input, uint32_t input_len) {
    MysqlServerHandshake hs;

    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }

    memset(&hs, 0, sizeof(hs));
    parseMysqlPktHdr(&hs.hdr, input);
    
    /* TODO: handshake message useless for now */

    return 0; 
}

static int parseClientAuth(MysqlState *state, uint8_t *input, uint32_t input_len) {
    MysqlClientAuth ca;
    uint8_t *p = input;
    int ret;
    uint32_t res;

    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }

    memset(&ca, 0, sizeof(ca));
    parseMysqlPktHdr(&ca.hdr, input);
    p += 4; /* skip header */

    if ((ret = ByteExtractUint32(&res, BYTE_BIG_ENDIAN, 4, p)) != 0) {
        return -1;
    }
    ca.client_available_attr = (int32_t)res;
    p += 4; /* skip client attr */

    if ((ret = ByteExtractUint32(&res, BYTE_BIG_ENDIAN, 4, p)) != 0) {
        return -1;
    }
    ca.max_pkt_len = res;
    p += 4; /* skip max packet length */

    ca.charset = *p;
    ++p;
    p += 23; /* skip reserved */

    state->cli.username = SCStrdup((char *)p); 

    ca.username = state->cli.username;
    p += strlen(ca.username); /* skip user name */

    ca.password_len = *p;
    ca.password = SCMalloc(ca.password_len);
    memcpy(ca.password, p, ca.password_len);
    p += ca.password_len;

    ca.initial_db_name = SCStrdup((char *)p);

    logUserLoginHist(state, &ca);
    return 0;
}

static int parseServerAuthResp(MysqlState *state, uint8_t *input, uint32_t input_len) {
    MysqlServerAuthResponse ar;
    uint8_t *p = input;

    if (input_len < 4) /* minimal length for Mysql packege */
        return -1;

    memset(&ar, 0, sizeof(ar));

    parseMysqlPktHdr(&ar.hdr, input);
    p += 4; /* skip header */

    ar.status = *p;
    ++p;

    /* TODO: do not need to do more, we just need login OK or fail */

    logLoginResp(state, &ar);
    return 0;
}

static int parseClientCmd(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    MysqlClientCommand cmd;
    uint8_t *p = input;

    if (input_len < 4)
        return -1;

    memset(&cmd, 0, sizeof(cmd));
    parseMysqlPktHdr(&cmd.hdr, input);
    p += 4;

    cmd.cmd = *p;
    ++p;
    cmd.sql = strdup((char *)p);

    logQueryHist(state, &cmd);
    return 0;
}

static int MysqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    MysqlState *state = (MysqlState *)alstate;
    SCEnter();

    int ret = -1;


    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            alstate, pstate, input, input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    switch (state->flags) {
        case MYSQL_STATE_SERVER_HANDSHAKE:
            if ((ret = parseClientAuth(state, input, input_len)) == 0)
                state->flags |= MYSQL_STATE_CLIENT_AUTH;
            break;
        case MYSQL_STATE_SERVER_RESPONSE:
        case MYSQL_STATE_SERVER_AUTH_RESP:
            if ((ret = parseClientCmd(state, input, input_len)) == 0)
                state->flags |= MYSQL_STATE_CLIENT_COMMAND;
            break;
        default:
            break;
            
    }

    /* TODO */
    return 0;
}

static int MysqlParseServerRecord(Flow *f, void *mysql_state,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    MysqlState *state = (MysqlState *)mysql_state;
    SCEnter();

    int ret = 0;

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            mysql_state, pstate, input, input_len);
    if (pstate == NULL)
        SCReturnInt(-1);
    
    switch (state->flags) {
        case MYSQL_STATE_INITIAL:
            if ((ret = parseServerHs(state, input, input_len)) == 0)
                state->flags |= MYSQL_STATE_SERVER_HANDSHAKE;
            break;
        case MYSQL_STATE_CLIENT_AUTH: /* connection */
            if ((ret = parseServerAuthResp(state, input, input_len)) == 0)
                state->flags |= MYSQL_STATE_SERVER_AUTH_RESP;
            break;
        case MYSQL_STATE_CLIENT_COMMAND:
            /* need parse response? */
            break;
        default:
            break;
    }

    if (ret) {
        ; /* TODO */
    }

    /* TODO */
    return 0;
}

static void *MysqlStateAlloc(void) {
    void *s = SCMalloc(sizeof(MysqlState));
    if (s == NULL)
        return NULL;
    memset(s, 0, sizeof(MysqlState));
    return s;
}

static void MysqlStateFree(void *state) {
    MysqlState *s = (MysqlState *)state;
    if (s->cli.username != NULL)
        SCFree(s->cli.username);
    SCFree(s);
}

void RegisterMysqlParsers(void) {
    char *proto_name = "mysql";

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        /* TODO:
         * Mysql protocol got no prefix in the protocol, so we capture every packages pass by 
         */
        AlpProtoAddCI(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_MYSQL, "||", 1, 0, STREAM_TOSERVER);
        AlpProtoAddCI(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_MYSQL, "||", 1, 0, STREAM_TOCLIENT);

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_MYSQL, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOSERVER, MysqlParseClientRecord);
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOCLIENT, MysqlParseServerRecord);
        AppLayerRegisterStateFuncs(ALPROTO_MYSQL, MysqlStateAlloc, MysqlStateFree);
    }

    return;
}
