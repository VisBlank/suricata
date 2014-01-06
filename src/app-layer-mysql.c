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
#include "conf.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* status */
#define MYSQL_STATE_INITIAL          0x00
#define MYSQL_STATE_SERVER_HANDSHAKE 0x01
#define MYSQL_STATE_CLIENT_AUTH      0x02
#define MYSQL_STATE_SERVER_AUTH_RESP 0x04
#define MYSQL_STATE_CLIENT_COMMAND   0x08
#define MYSQL_STATE_SERVER_RESPONSE  0x10
#define MYSQL_STATE_CLIENT_QUIT      0x20
#define MYSQL_STATE_INVALID          0x40

typedef enum {
	MYSQL_COMMAND_SLEEP               = 0x00, MYSQL_COMMAND_QUIT             = 0x01,
	MYSQL_COMMAND_INIT_DB             = 0x02, MYSQL_COMMAND_QUERY            = 0x03,
	MYSQL_COMMAND_FIELD_LIST          = 0x04, MYSQL_COMMAND_CREATE_DB        = 0x05,
	MYSQL_COMMAND_DROP_DB             = 0x06, MYSQL_COMMAND_REFRESH          = 0x07,
	MYSQL_COMMAND_SHUTDOWN            = 0x08, MYSQL_COMMAND_STATISTICS       = 0x09,
	MYSQL_COMMAND_PROCESS_INFO        = 0x0a, MYSQL_COMMAND_CONNECT          = 0x0b,
	MYSQL_COMMAND_PROCESS_KILL        = 0x0c, MYSQL_COMMAND_DEBUG            = 0x0d,
	MYSQL_COMMAND_PING                = 0x0e, MYSQL_COMMAND_TIME             = 0x0f,
	MYSQL_COMMAND_DELAYED_INSERT      = 0x10, MYSQL_COMMAND_CHANGE_USER      = 0x11,
	MYSQL_COMMAND_BINLOG_DUMP         = 0x12, MYSQL_COMMAND_TABLE_DUMP       = 0x13,
	MYSQL_COMMAND_CONNECT_OUT         = 0x14, MYSQL_COMMAND_REGISTER_SLAVE   = 0x15,
	MYSQL_COMMAND_STMT_PREPARE        = 0x16, MYSQL_COMMAND_STMT_EXECUTE     = 0x17,
	MYSQL_COMMAND_STMT_SEND_LONG_DATA = 0x18, MYSQL_COMMAND_STMT_CLOSE       = 0x19,
	MYSQL_COMMAND_STMT_RESET          = 0x1a, MYSQL_COMMAND_SET_OPTION       = 0x1b,
	MYSQL_COMMAND_STMT_FETCH          = 0x1c, MYSQL_COMMAND_DAEMON           = 0x1d,
	MYSQL_COMMAND_BINLOG_DUMP_GTID    = 0x1e, MYSQL_COMMAND_RESET_CONNECTION = 0x1f,

    /* commands not from Mysql, just append them */
    MYSQL_COMMAND_LOGIN               = 0x20,
    MYSQL_COMMAND_DO_NOT_EXIST /* do not declare command after me */
} MysqlRequestCommand;

static char *cmd_str[MYSQL_COMMAND_DO_NOT_EXIST] = {
	"SLEEP","QUIT",
	"INIT_DB","QUERY",
	"FIELD_LIST","CREATE_DB",
	"DROP_DB","REFRESH",
	"SHUTDOWN","STATISTICS",
	"PROCESS_INFO","CONNECT",
	"PROCESS_KILL","DEBUG",
	"PING","TIME",
	"DELAYED_INSERT","CHANGE_USER",
	"BINLOG_DUMP","TABLE_DUMP",
	"CONNECT_OUT","REGISTER_SLAVE",
	"STMT_PREPARE","STMT_EXECUTE",
	"STMT_SEND_LONG_DATA","STMT_CLOSE",
	"STMT_RESET","SET_OPTION",
	"STMT_FETCH","DAEMON",
	"BINLOG_DUMP_GTID","RESET_CONNECTION",
};

/* comes from include/mysql_com.h */
enum client_flags {
    CLIENT_LONG_PASSWORD       = 1      , /* new more secure passwords */
    CLIENT_FOUND_ROWS          = 2      , /* Found instead of affected rows */
    CLIENT_LONG_FLAG           = 4      , /* Get all column flags */
    CLIENT_CONNECT_WITH_DB     = 8      , /* One can specify db on connect */
    CLIENT_NO_SCHEMA           = 16     , /* Don't allow database.table.column */
    CLIENT_COMPRESS            = 32     , /* Can use compression protocol */
    CLIENT_ODBC                = 64     , /* Odbc client */
    CLIENT_LOCAL_FILES         = 128    , /* Can use LOAD DATA LOCAL */
    CLIENT_IGNORE_SPACE        = 256    , /* Ignore spaces before '(' */
    CLIENT_PROTOCOL_41         = 512    , /* New 4.1 protocol */
    CLIENT_INTERACTIVE         = 1024   , /* This is an interactive client */
    CLIENT_SSL                 = 2048   , /* Switch to SSL after handshake */
    CLIENT_IGNORE_SIGPIPE      = 4096   , /* IGNORE sigpipes */
    CLIENT_TRANSACTIONS        = 8192   , /* Client knows about transactions */
    CLIENT_RESERVED            = 16384  , /* Old flag for 4.1 protocol */
    CLIENT_SECURE_CONNECTION   = 32768  , /* New 4.1 authentication */
    CLIENT_MULTI_STATEMENTS    = 65536  , /* Enable/disable multi-stmt support */
    CLIENT_MULTI_RESULTS       = 131072 , /* Enable/disable multi-results */
};

enum pkt_flags {
    PKT_COMPLETE,
    PKT_INCOMPLETE_WITH_HEAD,
    PKT_INCOMPLETE_CAN_APPEND,
    PKT_INVALID,
};

typedef struct MysqlPkt_ {
    uint8_t *pkt;
    uint32_t len;
    int flags;
} MysqlPkt;

typedef struct MysqlClient_ {
    char *username;
    int client_attr; /* attributes the client support */
    int max_pkt_len;
    char *src_ip; /* TODO: only support IPv4 */
    char *dst_ip; /* TODO: only support IPv4 */
    uint16_t src_port;
    uint16_t dst_port;
    char *db_name;
    char *password; /* crypted, in hex bytes */
    char charset;
    char password_len;
    /* more to add */
} MysqlClient;

typedef struct PendingPkt_ {
    uint32_t pkt_len;
    uint32_t cur_len;
    uint8_t *pkt;
} PendingPkt;

typedef struct MysqlState_ {
    uint8_t flags;
    uint8_t cur_cmd;
    PendingPkt pending_pkt;
    MysqlClient cli;
    /* TODO: add more */
} MysqlState;

typedef struct MysqlPktHeader_ {
    uint32_t payload_len:24;
    int sequence_id:8;
} MysqlPktHeader;

/* not in use */
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
    int sql_size;
    char *sql;
} MysqlClientCommand;

/* not use */
typedef struct MysqlResponse_ {
    MysqlPktHeader hdr;
    /* TODO */
} MysqlResponse;

/* ================================================================== */
#define FMT_JSON 0
#define FMT_TXT  1

static int g_fd = -1;
static int g_log_fmt = FMT_JSON;
static int g_log_enabled = 0;
static int g_log_append = 0;
static char g_log_file_name[256];
static int LoadLogConf(void) {
    ConfNode *output = NULL, *output_config = NULL;
    ConfNode *outputs = ConfGetNode("outputs");
    ConfNode *default_dir = ConfGetNode("default-log-dir");
    size_t val_len;

    if (outputs == NULL)
        return -1;

    if (default_dir == NULL) {
        sprintf(g_log_file_name, "./");
    } else {
        val_len = strlen(default_dir->val);
        if (val_len >= 256) {
            return -1;
        }
        snprintf(g_log_file_name, val_len, "%s", default_dir->val);
        if (g_log_file_name[val_len] != '/')
            strcat(g_log_file_name, "/");
    }

    const char *val;
    TAILQ_FOREACH(output, &outputs->head, next) {
        if (strcmp(output->val, "mysql-log") == 0) {
            output_config = ConfNodeLookupChild(output, output->val);
            if (output_config == NULL) {
                return -1;
            }
            val = ConfNodeLookupChildValue(output_config, "enabled");
            if (val == NULL || !ConfValIsTrue(val))
                continue;
            else
                g_log_enabled = 1;

            val = ConfNodeLookupChildValue(output_config, "format");
            if (val == NULL)
                continue;
            else if (strcasecmp(val, "json") == 0)
                g_log_fmt = FMT_JSON;

            val = ConfNodeLookupChildValue(output_config, "filename");
            if (val == NULL)
                return -1;
            val_len += strlen(val);
            if (val_len > 256)
                return -1;
            strcat(g_log_file_name, val);

            val = ConfNodeLookupChildValue(output_config, "append");
            if (val == NULL || !ConfValIsTrue(val))
                continue;
            else
                g_log_append = 1;

            break;
        }
    }

    return 0;
}

static int InitLog(void) {
    int ret = LoadLogConf();
    if (ret == -1) {
        SCReturnInt(-1);
    }

    g_fd = open(g_log_file_name, O_RDWR);

    if (g_fd == -1) {
        /* create the file */
        g_fd = open(g_log_file_name, O_CREAT|O_RDWR, 0644);
        if (g_fd == -1)
            return -1;
        if (g_log_fmt == FMT_JSON)
            write(g_fd, "[\n]", 3);
    }

    if (g_log_append)
        fcntl(g_fd, F_SETFD, g_log_append);
    return 0;
}

void FlushLog(char *msg, size_t cnt) {
    if (g_fd == -1)
        return;
    lseek(g_fd, -1, SEEK_END); /* to overwirte the last `]' */
    write(g_fd, msg, cnt);
}

int ParseMysqlPktHdr(MysqlPktHeader *hdr, uint8_t *input, uint32_t input_len) {
    int ret;
    uint32_t res;

    if (input_len < 3) /* not a header */
        return -1;

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 3, input)) <= 0) {
        return -1;
    }

    if (hdr->payload_len + 4 < input_len) {
        return -1; /* we suppose input_len should not larger than payload_len */
    }

    hdr->payload_len = res;
    hdr->sequence_id = input[3];
    return 0;
}

void LogUserLoginHist(MysqlState *s) {
    char buf[256] = {0};

    if (!g_log_enabled)
        return;

    snprintf(buf, 256,
            "{time:%ld,src_ip:'%s',src_port:%d,dst_ip:'%s',dst_port:%d,"
            "db_type:'%s',user:'%s',db_name:'%s',operation:'%s', action:'%s',"
            "meta_info:{cmd:'%s',sql:'%s',}},\n]",
            (long)time(NULL),
            s->cli.src_ip, s->cli.src_port,
            s->cli.dst_ip, s->cli.dst_port,
            "mysql", s->cli.username,
            (s->cli.db_name ? s->cli.db_name: "null"),
            "LOGIN", "PASS", /* FIXME: default pass */
            "null", "null"); /* no sql during login */

    FlushLog(buf, strlen(buf));
}

void LogLoginResp(MysqlState *s, MysqlServerAuthResponse *ar) {
    /* TODO */
}

void LogQueryHist(MysqlState *s, MysqlClientCommand *cmd) {
    char buf[256] = {0};
    char *p = buf;
    int len = 256;

    if (!g_log_enabled)
        return;

    if (cmd->sql_size > 100) {
        p = SCCalloc(cmd->sql_size + 256, 1);
        len = cmd->sql_size + 256;
    }

    snprintf(p, len,
            "{time:%ld,src_ip:'%s',src_port:%d,dst_ip:'%s',dst_port:%d,"
            "db_type:'%s',user:'%s',db_name:'%s',operation:'%s', action:'%s',"
            "meta_info:{cmd:'%s',sql:'%s',}},\n]",
            (long)time(NULL),
            s->cli.src_ip, s->cli.src_port,
            s->cli.dst_ip, s->cli.dst_port,
            "mysql", s->cli.username,
            (s->cli.db_name ? s->cli.db_name: "null"),
            "DB_COMMAND", "PASS", /* FIXME: default pass */
            (cmd->cmd < MYSQL_COMMAND_DO_NOT_EXIST) ? cmd_str[(int)cmd->cmd] : "null",
            cmd->sql ? cmd->sql : "null");
    FlushLog(p, strlen(p));

    if (len > 256)
        SCFree(p);
}

static int ParseServerHs(MysqlState *s, uint8_t *input, uint32_t input_len) {
    MysqlServerHandshake hs;

    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }

    memset(&hs, 0, sizeof(hs));
    ParseMysqlPktHdr(&hs.hdr, input, input_len);

    /* TODO: handshake message useless for now */

    return 0;
}

static int ParseClientAuth(MysqlState *state, uint8_t *input, uint32_t input_len) {
    uint8_t *p = input;
    int ret;
    uint32_t res;
    MysqlPktHeader hdr;
    uint32_t parsed_len = 0;

    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }

    ParseMysqlPktHdr(&hdr, input, input_len);
    p += 4; /* skip header */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0) {
        return -1;
    }
    state->cli.client_attr = (int32_t)res;
    p += 4; /* skip client attr */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0) {
        return -1;
    }
    state->cli.max_pkt_len = res;
    p += 4; /* skip max packet length */

    state->cli.charset = *p;
    ++p;
    p += 23; /* skip reserved */

    state->cli.username = SCStrdup((char *)p);

    p += strlen(state->cli.username) + 1; /* skip user name plus '\0' */

    state->cli.password_len = *p;
    ++p; /* skip password length */
    parsed_len++;
    if (state->cli.password_len > 0) {
        state->cli.password = SCMalloc(state->cli.password_len);
        memcpy(state->cli.password, p, state->cli.password_len);
        p += state->cli.password_len;
    }

    if (*p != '\0') {
        parsed_len = p - input + 1;
        if (parsed_len + sizeof("mysql_native_password") - 1 < input_len) {
            /* db_name available */
            state->cli.db_name= SCStrdup((char *)p);
        }
    }

    state->cur_cmd = MYSQL_COMMAND_LOGIN;

    LogUserLoginHist(state);
    return 0;
}

static int ParseServerAuthResp(MysqlState *state, uint8_t *input, uint32_t input_len) {
    MysqlServerAuthResponse ar;
    uint8_t *p = input;

    if (input_len < 4) /* minimal length for Mysql packege */
        return -1;

    memset(&ar, 0, sizeof(ar));

    ParseMysqlPktHdr(&ar.hdr, input, input_len);
    p += 4; /* skip header */

    ar.status = *p;
    ++p;

    /* TODO: do not need to do more, we just need login OK or fail */

    LogLoginResp(state, &ar);
    return 0;
}

static int IsCompleteMysqlPacket(uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;
    if (ParseMysqlPktHdr(&hdr, input, input_len) == -1)
        return FALSE;
    if (input_len == (hdr.payload_len + 4))
        return TRUE;
    return FALSE;
}

static void CleanPendingPkt(PendingPkt *ppkt) {
    SCFree(ppkt->pkt);
    ppkt->pkt_len = 0;
    ppkt->cur_len = 0;
}

static void LogDroppedPendingPkt(MysqlState *s) {
    /* TODO */
}

static void LogDroppedPkt(MysqlState *state, uint8_t *input, uint32_t input_len) {

}

static int AppendPendingPkt(MysqlState *state, uint8_t *input, uint32_t input_len) {
    PendingPkt *ppkt = &state->pending_pkt;
    if (ppkt == NULL)
        return -1;
    if (ppkt->cur_len + input_len > ppkt->pkt_len) {
        /* lenght error, we suppose that the @input is not part of the @ppkt */
        LogDroppedPkt(state, input, input_len);
        return -1;
    } else {
        memcpy(ppkt->pkt + ppkt->cur_len, input, input_len);
        ppkt->cur_len += input_len;
        return 0;
    }
    return 0;
}


static int ParseCompleteMysqlClientPkt(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    MysqlClientCommand cmd;
    uint8_t *p = input;

    if (input_len < 4)
        return -1;

    memset(&cmd, 0, sizeof(cmd));
    ParseMysqlPktHdr(&cmd.hdr, input, input_len);
    p += 4;

    cmd.cmd = *p;
    ++p;
    state->cur_cmd = cmd.cmd;

    if (cmd.hdr.payload_len > 1) { /* at least have a command */
        cmd.sql = SCMalloc(cmd.hdr.payload_len);
        memcpy(cmd.sql, p, cmd.hdr.payload_len);
        cmd.sql[cmd.hdr.payload_len - 1] = 0;
        cmd.sql_size = cmd.hdr.payload_len;
    }

    LogQueryHist(state, &cmd);

    if (cmd.sql != NULL)
        SCFree(cmd.sql);
    return 0;
}

static int NoPending(MysqlState *state) {
    return (state->pending_pkt.pkt == NULL);
}

static void PreparsePkt(MysqlState *state, MysqlPkt *pkt, uint8_t *input, uint32_t input_len) {
    int ret = 0;
    MysqlPktHeader hdr;

    (void)state;

    pkt->flags = PKT_INVALID;
    pkt->pkt = input;
    pkt->len = input_len;
    ret = ParseMysqlPktHdr(&hdr, input, input_len);
    if (ret == -1) {
        /* we supporse this package can append to existing pending packets */
        pkt->flags = PKT_INCOMPLETE_CAN_APPEND;
        return;
    }

    if (hdr.payload_len + 4 == input_len) {
        pkt->flags = PKT_COMPLETE;
    } else if (hdr.payload_len + 4 < input_len) {
        pkt->flags = PKT_INVALID; /* FIXME */
    } else if (hdr.payload_len + 4 > input_len) {
        pkt->flags = PKT_INCOMPLETE_WITH_HEAD;
    }
        
    return;
}

static void InitPendingPkt(MysqlState *state, uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;

    if (ParseMysqlPktHdr(&hdr, input, input_len) == -1) { 
        LogDroppedPkt(state, input, input_len);
        return -1;
    }

    if ((hdr.payload_len + 4) < input_len) {
        LogDroppedPkt(state, input, input_len);
        return -1; /* input longer than MySQL packet ? */
    }

    state->pending_pkt.pkt_len = hdr.payload_len + 4;
    state->pending_pkt.pkt = SCMalloc(state->pending_pkt.pkt_len);
    memcpy(state->pending_pkt.pkt, input, input_len);
    state->pending_pkt.cur_len = input_len;
}

static int ParseClientCmd(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    MysqlPkt pkt;

    PreparsePkt(state, &pkt, input, input_len);

    switch (pkt.flags) {
        case PKT_COMPLETE:
            return ParseCompleteMysqlClientPkt(state, pkt.pkt, pkt.len);
        case PKT_INCOMPLETE_WITH_HEAD:
            if (NoPending(state)) {
                InitPendingPkt(state, pkt.pkt, pkt.len);
                return 0;
            } else {
                /* drop and release existing pending packages */
                CleanPendingPkt(&state->pending_pkt);
                InitPendingPkt(state, pkt.pkt, pkt.len);
            }
            break;
        case PKT_INCOMPLETE_CAN_APPEND:
            if (AppendPendingPkt(state, pkt.pkt, pkt.len) == -1) {
                /* append fail */
                SCReturnInt(0);
            }

            if (IsCompleteMysqlPacket(state->pending_pkt.pkt, state->pending_pkt.cur_len)) {
                int ret = ParseCompleteMysqlClientPkt(state, state->pending_pkt.pkt,
                        state->pending_pkt.cur_len);
                CleanPendingPkt(&state->pending_pkt);
                return ret;
            }
            break;
        default:
            SCReturnInt(-1);
    }
    SCReturnInt(-1);
}

void DumpPkt(MysqlState *state, uint8_t *input, uint32_t input_len, uint8_t **dump) {
    /* TODO */
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
        case MYSQL_STATE_SERVER_HANDSHAKE:{
            struct in_addr *ia = (struct in_addr *)&f->src.address.address_un_data32[0];
            char *ip = inet_ntoa(*ia);
            state->cli.src_ip = SCStrdup(ip);
            state->cli.src_port = f->sp;

            ia = (struct in_addr *)&f->dst.address.address_un_data32[0];
            ip = inet_ntoa(*ia);
            state->cli.dst_ip = SCStrdup(ip);
            state->cli.dst_port = f->dp;

            if ((ret = ParseClientAuth(state, input, input_len)) == 0) {
                state->flags = MYSQL_STATE_CLIENT_AUTH;
            }
                                          }
            break;
        case MYSQL_STATE_SERVER_RESPONSE:
        case MYSQL_STATE_SERVER_AUTH_RESP: {
            if ((ret = ParseClientCmd(state, input, input_len)) == 0) {
                (state->cur_cmd == MYSQL_COMMAND_QUIT) ?
                    (state->flags = MYSQL_STATE_CLIENT_QUIT):
                    (state->flags = MYSQL_STATE_CLIENT_COMMAND);
            } else {
                uint8_t *dump = NULL;
                DumpPkt(state, input, input_len, &dump);
                SCLogError(SC_ERR_INVALID_PACKET, "%s", dump);
            }
            break;
                                           }
        default:
            state->flags = MYSQL_STATE_INVALID;
            return ret;;
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
            if ((ret = ParseServerHs(state, input, input_len)) == 0)
                state->flags = MYSQL_STATE_SERVER_HANDSHAKE;
            break;
        case MYSQL_STATE_CLIENT_AUTH: /* connection */
            if ((ret = ParseServerAuthResp(state, input, input_len)) == 0)
                state->flags = MYSQL_STATE_SERVER_AUTH_RESP;
            break;
        case MYSQL_STATE_CLIENT_COMMAND:
            /* need parse response? */
            state->flags = MYSQL_STATE_SERVER_RESPONSE;
            break;
        default:
            state->flags = MYSQL_STATE_INVALID;
            return ret;;
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

    if (s->cli.db_name!= NULL)
        SCFree(s->cli.db_name);

    if (s->cli.password!= NULL)
        SCFree(s->cli.password);

    if (s->cli.src_ip != NULL)
        SCFree(s->cli.src_ip);

    if (s->cli.dst_ip != NULL)
        SCFree(s->cli.dst_ip);

    SCFree(s);
}

static int MysqlRequestParse(uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;
    ParseMysqlPktHdr(&hdr, input, input_len);

    /* meet the basic requirement for a MySQL packet */
#if 0
    if (hdr.payload_len == input_len - 4) {
            SCReturnInt(1);
    }
    SCReturnInt(-1);
#endif
    SCReturnInt(1);
}

static uint16_t MysqlProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0 || ilen < sizeof(MysqlPktHeader)) {
        return ALPROTO_UNKNOWN;
    }

    if (MysqlRequestParse(input, ilen) == -1) {
        return ALPROTO_FAILED;
    }

    return ALPROTO_MYSQL;
}

void RegisterMysqlParsers(void) {
    char *proto_name = "mysql";

    if (InitLog() != 0) {
        return;
    }

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        AppLayerParseProbingParserPorts(proto_name, ALPROTO_MYSQL, 0,
                sizeof(MysqlPktHeader), MysqlProbingParser);

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
