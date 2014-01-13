/**
 * \file
 * \author
 *
 * App-layer parser for Mysql protocol
 *
 */

#include "suricata-common.h"
#include "app-layer-mysql-common.h"

#include "conf.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static char *cmd_str[] = {
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
    size_t val_len = 0;

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
    if (ret == -1 || g_log_enabled == 0) {
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
    if (g_fd == -1) {
        /* FIXME: default print message */
        printf("%s", msg);
        return;
    }
    lseek(g_fd, -1, SEEK_END); /* to overwirte the last `]' */
    write(g_fd, msg, cnt);
}

void LogUserLoginHist(MysqlState *s) {
    char buf[256] = {0};
#if 0
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
#endif
}

#if 0
void LogLoginResp(MysqlState *s, MysqlServerAuthResponse *ar) {
    /* TODO */
}

void LogQueryHist(MysqlState *s, MysqlClientCommand *cmd) {
    char buf[256] = {0};
    char *p = buf;
    int len = 256;
    if (cmd->sql_size > 100) {
        p = SCCalloc(cmd->sql_size + 256, 1);
        len = cmd->sql_size + 256;
    }

    snprintf(p, len,
            "{time:%ld,src_ip:'%s',src_port:%d,dst_ip:'%s',dst_port:%d,"
            "db_type:'%s',user:'%s',db_name:'%s',operation:'%s', action:'%s',"
            "meta_info:{cmd:'%s',sql:'%s',}},\n]",
            (long)time(NULL),
            (s->cli.src_ip ? s->cli.src_ip : "null"), s->cli.src_port,
            (s->cli.dst_ip ? s->cli.dst_ip : "null"), s->cli.dst_port,
            "mysql", s->cli.username ? s->cli.username : "null",
            (s->cli.db_name ? s->cli.db_name: "null"),
            "DB_COMMAND", "PASS", /* FIXME: default pass */
            (cmd->cmd < MYSQL_COMMAND_DO_NOT_EXIST) ? cmd_str[(int)cmd->cmd] : "null",
            (cmd->sql ? cmd->sql : "null"));
    FlushLog(p, strlen(p));
    if (len > 256)
        SCFree(p);
}

static void LogDroppedPendingPkt(MysqlState *s) {
    /* TODO */
}

static void LogDroppedPkt(MysqlState *state, uint8_t *input, uint32_t input_len) {

}

void DumpPkt(MysqlState *state, uint8_t *input, uint32_t input_len, uint8_t **dump) {
    /* TODO */
}
#endif

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
        SCLogDebug("init log for mysql fail:");
        SCLogInfo("mysql log send to stdin:");
    }

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        if (RunmodeIsUnittests()) {
            AppLayerRegisterProbingParser(&alp_proto_ctx,
                    IPPROTO_TCP, "3306", proto_name,
                    ALPROTO_MYSQL, 0, sizeof(MysqlPktHeader),
                    STREAM_TOSERVER, MysqlProbingParser);
        } else {
            AppLayerParseProbingParserPorts(proto_name, ALPROTO_MYSQL, 0,
                    sizeof(MysqlPktHeader), MysqlProbingParser);

        }

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

#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_MYSQL, MysqlParserRegisterTests);
#endif

    return;
}

#if 0
#ifdef UNITTESTS
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "flow-util.h"
#include "util-unittest.h"

/** \test Server Send a handshake request in one chunk */
int MysqlParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x36, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x35,     0x2e, 0x32, 0x2d, 0x6d, 0x32, 0x00, 0x0b, 0x00,
        0x00, 0x00, 0x64, 0x76, 0x48, 0x40, 0x49, 0x2d,     0x43, 0x4a, 0x00, 0xff, 0xf7, 0x08, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x34, 0x64,
        0x7c, 0x63, 0x5a, 0x77, 0x6b, 0x34, 0x5e, 0x5d,     0x3a, 0x00 }; 
    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f,
            ALPROTO_MYSQL, STREAM_TOCLIENT | STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    MysqlState *s = f.alstate;
    if (s == NULL) {
        SCLogDebug("no mysql state: ");
        result = 0;
        goto end;
    }

    if (s->state != MYSQL_STATE_SERVER_HANDSHAKE) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s->cur_cmd);   
        result = 0;
        goto end;
    }
end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a login request in one chunk */
int MysqlParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0xb2, 0x00, 0x00, 0x01, 0x85, 0xa2, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14, 0x22, 0x50, 0x79, 0xa2, 0x12, 0xd4,
        0xe8, 0x82, 0xe5, 0xb3, 0xf4, 0x1a, 0x97, 0x75, 0x6b, 0xc8, 0xbe, 0xdb, 0x9f, 0x80, 0x6d, 0x79,
        0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77,
        0x6f, 0x72, 0x64, 0x00, 0x61, 0x03, 0x5f, 0x6f, 0x73, 0x09, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e,
        0x36, 0x2e, 0x30, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
        0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x04, 0x5f, 0x70, 0x69, 0x64, 0x05, 0x32,
        0x32, 0x33, 0x34, 0x34, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72,
        0x73, 0x69, 0x6f, 0x6e, 0x08, 0x35, 0x2e, 0x36, 0x2e, 0x36, 0x2d, 0x6d, 0x39, 0x09, 0x5f, 0x70,
        0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x03, 0x66,
        0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState s;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&s, 0, sizeof(s));

    s.state = MYSQL_STATE_SERVER_HANDSHAKE;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = &s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (s.cur_cmd != MYSQL_COMMAND_LOGIN) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s.cur_cmd);
        result = 0;
        goto end;
    }

    if (s.state != MYSQL_STATE_CLIENT_AUTH) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_STATE_CLIENT_AUTH, s.state);   
        result = 0;
        goto end;
    }
end:
    MysqlStateClean(&s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a query request in one chunk */
int MysqlParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, 0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState s;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&s, 0, sizeof(s));

    s.state = MYSQL_STATE_SERVER_RESPONSE;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = &s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

#if 0
    if (s.cur_cmd != MYSQL_COMMAND_LOGIN) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s.cur_cmd);
        result = 0;
        goto end;
    }
#endif

    if (s.state != MYSQL_STATE_CLIENT_COMMAND) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_STATE_CLIENT_COMMAND, s.state);   
        result = 0;
        goto end;
    }
end:
    MysqlStateClean(&s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a incomplete query request */
static MysqlState incomplete_state;
int MysqlParserTest04(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, //0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = &incomplete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    if (s->cur_cmd != MYSQL_COMMAND_PENDING)
        memset(&incomplete_state, 0, sizeof(incomplete_state));

    s->state = MYSQL_STATE_SERVER_RESPONSE;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* for incomplete package, do not parse the pkt, so there is no cmd parsed */
    if (s->cur_cmd != MYSQL_COMMAND_PENDING) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s->cur_cmd);
        result = 0;
        goto end;
    }

    if (s->state != MYSQL_STATE_CLIENT_COMMAND) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_STATE_CLIENT_COMMAND, s->state);   
        result = 0;
        goto end;
    }
end:
    MysqlStateClean(s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send the rest of the query request */
int MysqlParserTest05(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = &incomplete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    s->state = MYSQL_STATE_SERVER_RESPONSE;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (s->cur_cmd != MYSQL_COMMAND_QUERY) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s->cur_cmd);
        result = 0;
        goto end;
    }

    if (s->state != MYSQL_STATE_CLIENT_COMMAND) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_STATE_CLIENT_COMMAND, s->state);   
        result = 0;
        goto end;
    }
end:
    MysqlStateClean(s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a new command when there was a pending request */
int MysqlParserTest06(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, 0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = &incomplete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    s->state = MYSQL_STATE_SERVER_RESPONSE;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (s->cur_cmd != MYSQL_COMMAND_QUERY) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", MYSQL_COMMAND_LOGIN, s->cur_cmd);
        result = 0;
        goto end;
    }

    if (s->state != MYSQL_STATE_CLIENT_COMMAND) {
        SCLogDebug("expected state %" PRIu32 ", got %" PRIu32 ": ", MYSQL_STATE_CLIENT_COMMAND, s->state);   
        result = 0;
        goto end;
    }
end:
    MysqlStateClean(s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif
#endif

void MysqlParserRegisterTests(void) {
#ifdef UNITTESTS
#if 0
    UtRegisterTest("MysqlParserTest01", MysqlParserTest01, 1);
    UtRegisterTest("MysqlParserTest02", MysqlParserTest02, 1);
    UtRegisterTest("MysqlParserTest03", MysqlParserTest03, 1);

    /* porcess separated packet */
    UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);
    UtRegisterTest("MysqlParserTest05", MysqlParserTest05, 1);

    /* successive incomplete packet */
    UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);
    UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);

    /* process complete packet again on old mysql state */
    UtRegisterTest("MysqlParserTest06", MysqlParserTest06, 1);
#endif
#endif
}
