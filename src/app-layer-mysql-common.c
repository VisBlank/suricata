/**
 * \file
 * \author
 *
 * MySQL related features to release burden on app-layer-mysql
 */

#include "app-layer-mysql-common.h"

#define MYSQL_HDR_LEN 4

int ParseMysqlPktHdr(MysqlPktHeader *hdr, uint8_t *input, uint32_t input_len) {
    int ret;
    uint32_t res;

    if (input_len < MYSQL_HDR_LEN) /* not a header */
        return -1;

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, MYSQL_HDR_LEN, input)) <= 0) {
        return -1;
    }

    if (res < input_len - MYSQL_HDR_LEN) {
        return -1; /* we suppose input_len should not larger than payload_len */
    }

    hdr->payload_len = res;
    hdr->sequence_id = input[MYSQL_HDR_LEN];
    return 0;
}

static int ParseServerHs(MysqlState *s, uint8_t *input, uint32_t input_len) {
    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }
    
    uint8_t *p = input;
    MysqlPktHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    ParseMysqlPktHdr(&hdr, input, input_len);
    p += MYSQL_HDR_LEN;
    p += 24;

    uint32_t res;
    int ret = 0;
    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, sizeof(int), p)) <= 0)
        return -1;

    int conn_id = res; 
    MysqlTransaction *tx = NULL;
    if (s->cur_tx == NULL) {
        tx = MysqlTransactionAlloc();
        if (!tx)
            return -1;
        s->cur_tx = tx;
        TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    }

    s->cur_tx->tx_id = conn_id;
    s->cur_tx->tx_num++;

    /* TODO: handshake message useless for now */

    s->cur_tx->hs = 1;
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
    p += MYSQL_HDR_LEN; /* skip header and sequence */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0)
        return -1;

    state->cur_tx->cli.client_attr = (int32_t)res;
    p += 4; /* skip client attr */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0)
        return -1;

    state->cur_tx->cli.max_pkt_len = res;
    p += 4; /* skip max packet length */

    state->cur_tx->cli.charset = *p;
    ++p;
    p += 23; /* skip reserved */

    state->cur_tx->cli.username = SCStrdup((char *)p);

    p += strlen(state->cur_tx->cli.username) + 1; /* skip user name plus '\0' */

    state->cur_tx->cli.password_len = *p;
    ++p; /* skip password length */
    parsed_len++;

    if (state->cur_tx->cli.password_len > 0) {
        state->cur_tx->cli.password = SCMalloc(state->cur_tx->cli.password_len);
        memcpy(state->cur_tx->cli.password, p, state->cur_tx->cli.password_len);
        p += state->cur_tx->cli.password_len;
    }

    if (*p != '\0') {
        parsed_len = p - input + 1;
        if (parsed_len + sizeof("mysql_native_password") - 1 < input_len) {
            /* db_name available */
            state->cur_tx->cli.db_name= SCStrdup((char *)p);
        }
    }

    state->cur_tx->try_auth = 1;
    return 0;
}

static int ParseServerAuthResp(MysqlState *state, uint8_t *input, uint32_t input_len) {
    uint8_t *p = input;

    if (input_len < 4) /* minimal length for Mysql packege */
        return -1;

    MysqlPktHeader hdr;
    ParseMysqlPktHdr(&hdr, input, input_len);
    p += 4; /* skip header */

    char status = *p;

    /* login OK or fail? */
    if (status == 0) {
        state->cur_tx->auth_ok = 1;
        return 0;
    }

    return -1;
}

static int IsComplete(PendingPkt *ppkt) {
    MysqlPktHeader hdr;
    if (ParseMysqlPktHdr(&hdr, ppkt->pkt, ppkt->cur_len) == -1)
        return FALSE;
    if (ppkt->cur_len - MYSQL_HDR_LEN == hdr.payload_len)
        return TRUE;
    return FALSE;
}

static int TryAppendPkt(PendingPkt *ppkt, uint8_t *input, uint32_t input_len) {
    if (ppkt == NULL)
        return -1;
    if (ppkt->cur_len + input_len > ppkt->pkt_len) {
        /* lenght error, we suppose that the @input is not part of the @ppkt */
        ppkt->flags = PPKT_DROP;
        return -1;
    } else {
        memcpy(ppkt->pkt + ppkt->cur_len, input, input_len);
        ppkt->cur_len += input_len;
        return 0;
    }
    return 0;
}

void ResetCmd(MysqlClientCommand *cmd) {
    if (!cmd)
        return;
   if (cmd->sql != NULL) 
       SCFree(cmd->sql);
   memset(cmd, 0, sizeof(*cmd));
}

static int ParseCompleteMysqlClientPkt(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    MysqlClientCommand *cmd = &state->cur_tx->cmd;
    uint8_t *p = input;

    if (input_len < 4)
        return -1;

    ResetCmd(cmd);
    ParseMysqlPktHdr(&cmd->hdr, input, input_len);
    p += 4;

    cmd->cmd = *p;
    ++p;

    if (cmd->hdr.payload_len > 1) { /* at least have a command */
        cmd->sql = SCMalloc(cmd->hdr.payload_len);
        memcpy(cmd->sql, p, cmd->hdr.payload_len);
        cmd->sql[cmd->hdr.payload_len - 1] = 0;
        cmd->sql_size = cmd->hdr.payload_len;
    }

    return 0;
}

enum pkt_flags {
    PKT_COMPLETE,
    PKT_INCOMPLETE_WITH_HEAD,
    PKT_INCOMPLETE_CAN_APPEND,
    PKT_INVALID,
};

static int CheckPkt(uint8_t *input, uint32_t input_len) {
    int ret = 0;
    MysqlPktHeader hdr;
    ret = ParseMysqlPktHdr(&hdr, input, input_len);

    if (ret == -1) {
        /* we supporse this package can append to existing pending packets */
        return PKT_INCOMPLETE_CAN_APPEND;
    }

    if (hdr.payload_len == input_len - MYSQL_HDR_LEN) {
        return PKT_COMPLETE;
    } else if (hdr.payload_len < input_len - MYSQL_HDR_LEN) {
        return PKT_INVALID; /* FIXME */
    } else if (hdr.payload_len > input_len - MYSQL_HDR_LEN) {
        return PKT_INCOMPLETE_WITH_HEAD;
    }
        
    return PKT_INVALID;
}

static int InitPendingPkt(PendingPkt *ppkt, uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;
    if (!ppkt)
        return -1;

    if (ParseMysqlPktHdr(&hdr, input, input_len) == -1) {
        return -1;
    }

    if (hdr.payload_len < input_len - MYSQL_HDR_LEN) {
        return -1; /* input longer than MySQL packet ? */
    }

    ppkt->pkt_len = hdr.payload_len + MYSQL_HDR_LEN;
    ppkt->pkt = SCMalloc(ppkt->pkt_len);
    memcpy(ppkt->pkt, input, input_len);
    ppkt->cur_len = input_len;
    ppkt->flags = PPKT_APPENDING;
    return 0;
}

static int ParseServerCmdResp(MysqlState *state, uint8_t *input, uint32_t input_len) {
    /* TODO */
    return 0;
}

static int ParseClientCmd(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    int ret = 0;
    int res = CheckPkt(input, input_len);
    PendingPkt *ppkt = NULL, *cur_ppkt = state->cur_tx->cur_ppkt;

    switch (res) {
        case PKT_COMPLETE:
            return ParseCompleteMysqlClientPkt(state, input, input_len);
        case PKT_INCOMPLETE_WITH_HEAD:
            if (cur_ppkt ) {
                /* incoming pkt is another new message, the old append
                 * pkt supposed to be dropped */
                if (cur_ppkt->flags == PPKT_APPENDING)
                    cur_ppkt->flags = PPKT_DROP;
            }

            /* add new ppkt */
            ppkt = SCMalloc(sizeof(*ppkt));
            if (unlikely(ppkt == NULL)) {
                /* TODO: we should set some hint to the transaction */
                return -1;
            }

            if (InitPendingPkt(ppkt, input, input_len) == -1) {
                return -1;
            }

            TAILQ_INSERT_HEAD(&state->cur_tx->ppkt_list, ppkt, next);
            state->cur_tx->cur_ppkt = ppkt;

            return 0;
        case PKT_INCOMPLETE_CAN_APPEND:
            if (TryAppendPkt(cur_ppkt, input, input_len) == -1) {
                /* append fail */
                SCReturnInt(0);
            }

            if (IsComplete(cur_ppkt)) {
                ret = ParseCompleteMysqlClientPkt(state, cur_ppkt->pkt, cur_ppkt->cur_len);
                cur_ppkt->flags = PPKT_COMPLETE;
                /* we'll remove/release these ppkts in MysqlStateFree */
                return ret;
            }
            break;
        default:
            SCReturnInt(-1);
    }

    SCReturnInt(-1);
}

int MysqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    MysqlState *state = (MysqlState *)alstate;
    SCEnter();

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            alstate, pstate, input, input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    if (!state->cur_tx->try_auth) {
        return ParseClientAuth(state, input, input_len);
    } else {
        return ParseClientCmd(state, input, input_len);
    }

    SCReturnInt(-1);
}

int MysqlParseServerRecord(Flow *f, void *mysql_state,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    MysqlState *state = (MysqlState *)mysql_state;
    SCEnter();

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            mysql_state, pstate, input, input_len);
    if (pstate == NULL)
        SCReturnInt(-1);

    if (state->cur_tx == NULL) {
        MysqlTransaction *tx = MysqlTransactionAlloc();
        if (!tx) {
            return -1;
        }
        TAILQ_INSERT_HEAD(&state->tx_list, tx, next);
        state->cur_tx = tx;
    }

    if (!state->cur_tx->hs) {
        return ParseServerHs(state, input, input_len);
    } else if (!state->cur_tx->auth_ok) {
        return ParseServerAuthResp(state, input, input_len);
    } else  {
        return ParseServerCmdResp(state, input, input_len);
    }

    SCReturnInt(-1);
}

void *MysqlStateAlloc(void) {
    static uint8_t proto[] = "mysql";
    MysqlState *s = SCMalloc(sizeof(MysqlState));
    if (s == NULL)
        return NULL;
    memset(s, 0, sizeof(MysqlState));
    s->protocol_name = proto;

    TAILQ_INIT(&s->tx_list);
    return s;
}

void MysqlStateClean(MysqlState *ms) {
    /* TODO */
    MysqlClient *c = &ms->cur_tx->cli;
    if (c->username != NULL)
        SCFree(c->username);
    if (c->db_name != NULL)
        SCFree(c->db_name);

    if (c->password != NULL)
        SCFree(c->password);

    if (c->src_ip != NULL)
        SCFree(c->src_ip);

    if (c->dst_ip != NULL)
        SCFree(c->dst_ip);
}

void *MysqlTransactionAlloc() {
    MysqlTransaction *tx = SCMalloc(sizeof(MysqlTransaction));
    if (unlikely(tx == NULL))
        return NULL;
    memset(tx, 0, sizeof(*tx));
    TAILQ_INIT(&tx->ppkt_list);
    return tx;
}

void PendingPktFree(void *ppkt) {
    if (ppkt == NULL)
        return;
    PendingPkt *p = ppkt;
    if (p->pkt != NULL)
        SCFree(p->pkt);
    SCFree(p);
}

void MysqlTransactionFree(void *trans) {
    MysqlTransaction *tx = (MysqlTransaction *)trans;
    if (tx == NULL)
        SCReturn;

    if (tx->cli.username != NULL)
        SCFree(tx->cli.username);

    if (tx->cli.db_name!= NULL)
        SCFree(tx->cli.db_name);

    if (tx->cli.password!= NULL)
        SCFree(tx->cli.password);

    if (tx->cli.src_ip != NULL)
        SCFree(tx->cli.src_ip);

    if (tx->cli.dst_ip != NULL)
        SCFree(tx->cli.dst_ip);

    if (tx->cmd.sql != NULL)
        SCFree(tx->cmd.sql);

    PendingPkt *ppkt;
    while ((ppkt = TAILQ_FIRST(&tx->ppkt_list))) {
        TAILQ_REMOVE(&tx->ppkt_list, ppkt, next);
        PendingPktFree(ppkt);
    }

    SCFree(tx);
}

void MysqlStateFree(void *ms) {
    SCEnter();
    if (ms) {
        MysqlState *s = (MysqlState *)ms;
        MysqlTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&s->tx_list))) {
            TAILQ_REMOVE(&s->tx_list, tx, next);
            MysqlTransactionFree(tx);
        }
        SCFree(s);
    }
    SCReturn;
}

int MysqlRequestParse(uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;
    ParseMysqlPktHdr(&hdr, input, input_len);
    
    /* do nothing here */
    SCReturnInt(1);
}

const char *CmdStr(MysqlCommand cmd) {
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
        "LOGIN",
        "PENDING",
        "DO_NOT_EXIST",
    };

    if (cmd >= sizeof(cmd_str)/sizeof(char*))
        return cmd_str[sizeof(cmd_str)/sizeof(char*) - 1]; 
    return cmd_str[cmd];
}
