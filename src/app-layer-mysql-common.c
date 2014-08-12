/**
 * \file
 * \author
 *
 * MySQL related features to release burden on app-layer-mysql
 */

#include "app-layer-mysql-common.h"
#include "detect-threshold.h"

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

static MysqlTransaction *MysqlTransactionAlloc() {
    MysqlTransaction *tx = SCCalloc(1, sizeof(MysqlTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }
    return tx;
}

void MysqlTransactionFree(void *trans) {
    MysqlTransaction *tx = (MysqlTransaction *)trans;
    if (tx == NULL)
        SCReturn;

    if (tx->sql != NULL)
        SCFree(tx->sql);

    SCFree(tx);
}

static MysqlTransaction *InsertTx(MysqlState *s) {
    MysqlTransaction *tx = MysqlTransactionAlloc();

    tx->s = s;

    if (!s->cur_tx) {
        tx->tx_id = 0; /* the first transection */
    } else {
        tx->tx_id = s->cur_tx->tx_id + 1; /* tx_id is accumulative */
    }

    /* add to @s */
    s->cur_tx = tx;
    TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    s->tx_num++;

    /* return tx for convenient */
    return tx;
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

    /* TODO: handshake message useless for now, just label it */
    s->hs = 1;
    return 0;
}

static int ParseClientAuth(MysqlState *state, uint8_t *input, uint32_t input_len) {
    uint8_t *p = input;
    int ret;
    uint32_t res;

    if (input_len < 4) { /* minimal length for Mysql packege */
        return -1;
    }

    ParseMysqlPktHdr(&state->hdr, input, input_len);
    p += MYSQL_HDR_LEN; /* skip header and sequence */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0)
        return -1;

    state->cli.client_attr = (int32_t)res;
    p += 4; /* skip client attr */

    if ((ret = ByteExtractUint32(&res, BYTE_LITTLE_ENDIAN, 4, p)) <= 0)
        return -1;

    state->cli.max_pkt_len = res;
    p += 4; /* skip max packet length */

    state->cli.charset = *p;
    ++p;
    p += 23; /* skip reserved */

    state->cli.username = SCStrdup((char *)p);

    p += strlen(state->cli.username) + 1; /* skip user name plus '\0' */

    char pass_len = *p;
    if (pass_len > 0) { /* password len */
        ++p; /* skip len byte */
        p += pass_len; /* skip password */
    }

    if (*p != '\0') {
        /* From wireshark, we assure that there was a `\0` at the end of @input, so we
         * can use strncmp to detect the db name without segment error */
        if (strncmp((const char *)p, "mysql_native_password", sizeof(sizeof("mysql_native_password") - 1)) != 0) {
            /* db name presented */
            state->cli.db_name= SCStrdup((char *)p);
        }
    }

    state->try_auth = 1;

    MysqlTransaction *tx = InsertTx(state);
    tx->cmd = MYSQL_COMMAND_LOGIN;
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
        state->auth_ok = 1;
        return 0;
    } else {
        ;/* TODO: on login fail, should we drop the state? */
    }

    return -1;
}

static int ParseCompleteMysqlClientPkt(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    MysqlTransaction *tx= InsertTx(state);
    uint8_t *p = input;

    if (input_len < 4)
        return -1;

    ParseMysqlPktHdr(&state->hdr, input, input_len);
    p += 4;

    tx->cmd = *p;
    ++p;

    if (state->hdr.payload_len > 1) { /* at least have a command */
        tx->sql = SCMalloc(state->hdr.payload_len);
        memcpy(tx->sql, p, state->hdr.payload_len);
        tx->sql[state->hdr.payload_len - 1] = 0;
        tx->sql_len = state->hdr.payload_len;
    }

    return 0;
}

enum pkt_flags {
    PKT_COMPLETE,
    PKT_INCOMPLETE_WITH_HEAD,
    PKT_INCOMPLETE_CAN_APPEND,
    PKT_INVALID,
};

static int CheckPkt(MysqlState *s, uint8_t *input, uint32_t input_len) {
    int ret = 0;
    MysqlPktHeader hdr;

    ret = ParseMysqlPktHdr(&hdr, input, input_len);

    if (ret == -1) {
        /* we supporse this package can append to existing pending packets */
        return PKT_INVALID;
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

#if 0
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
#endif

static int ParseServerCmdResp(MysqlState *state, uint8_t *input, uint32_t input_len) {
    /* TODO */
    return 0;
}

static int ParseClientCmd(MysqlState *state, uint8_t *input, uint32_t input_len)  {
    int res = 0;
    if (state->pending && state->recved_len + input_len == state->payload_len)
        res = PKT_INCOMPLETE_CAN_APPEND;
    else
        res = CheckPkt(state, input, input_len);

    switch (res) {
        case PKT_COMPLETE:
            return ParseCompleteMysqlClientPkt(state, input, input_len);
        case PKT_INCOMPLETE_WITH_HEAD:
            state->pending = TRUE;
            /* we include header bytes into payload, because successive
             * pending bytes will not include header bytes, and at last
             * we need to parse the complete pkt with header */ 
            
            ParseMysqlPktHdr(&state->hdr, input, input_len);
            state->payload_len = state->hdr.payload_len + MYSQL_HDR_LEN;
            state->payload = SCCalloc(1, state->payload_len);
            memcpy(state->payload, input, input_len);
            state->recved_len = input_len;

            SCReturnInt(0);
        case PKT_INCOMPLETE_CAN_APPEND:
            memcpy(state->payload + state->recved_len, input, input_len);
            state->recved_len += input_len;
            
            if (state->recved_len == state->payload_len) {
                if (ParseCompleteMysqlClientPkt(state, state->payload, state->payload_len) == 0) {
                    state->pending = FALSE;

                    SCFree(state->payload);
                    state->payload = NULL;
                    state->recved_len = 0;
                    state->payload_len = 0;
                    SCReturnInt(0);
                }
            }

        default:
            SCReturnInt(-1);
    }

    SCReturnInt(-1);
}

int MysqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data) {
    MysqlState *state = (MysqlState *)alstate;
    SCEnter();

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            alstate, pstate, input, input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    if (!state->try_auth) {
        return ParseClientAuth(state, input, input_len);
    } else {
        return ParseClientCmd(state, input, input_len);
    }

    SCReturnInt(-1);
}

int MysqlParseServerRecord(Flow *f, void *mysql_state,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data) {
    MysqlState *state = (MysqlState *)mysql_state;
    SCEnter();

    SCLogDebug("mysql_state %p, pstate %p, input %p, input_len %" PRIu32 "",
            mysql_state, pstate, input, input_len);
    if (pstate == NULL)
        SCReturnInt(-1);

    /* do not set transection for server response */
#if 0
    MysqlTransaction *tx = InsertTx(state, input, input_len);
    if (unlikely(!tx)) {
        SCReturnInt(-1);
    }
#endif

    /* FIXME: We also parse the server response, if iptables
     * do not forward server response to NFQ, we may fail
     * on state transition, and I think this is a serious bug */
    if (!state->hs) {
        return ParseServerHs(state, input, input_len);
    } else if (!state->auth_ok) {
        return ParseServerAuthResp(state, input, input_len);
    } else  {
        return ParseServerCmdResp(state, input, input_len);
    }

    SCReturnInt(-1);
}

void *MysqlStateAlloc(void) {
    static uint8_t proto[] = "mysql";
    MysqlState *s = SCCalloc(sizeof(MysqlState), 1);
    if (s == NULL)
        return NULL;
    s->protocol_name = proto;

    TAILQ_INIT(&s->tx_list);
    return s;
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

        if (s->pending)
            SCFree(s->payload);

        SCFree(s);
    }
}

int MysqlRequestParse(uint8_t *input, uint32_t input_len) {
    MysqlPktHeader hdr;
    ParseMysqlPktHdr(&hdr, input, input_len);
    
    /* do nothing here */
    SCReturnInt(1);
}

#define MYSQL_CMD(cmd) case cmd: return #cmd
const char *CmdStr(MysqlCommand cmd) {
    switch (cmd) {
        MYSQL_CMD(MYSQL_COMMAND_SLEEP)              ;
        MYSQL_CMD(MYSQL_COMMAND_INIT_DB)            ;
        MYSQL_CMD(MYSQL_COMMAND_FIELD_LIST)         ;
        MYSQL_CMD(MYSQL_COMMAND_DROP_DB)            ;
        MYSQL_CMD(MYSQL_COMMAND_SHUTDOWN)           ;
        MYSQL_CMD(MYSQL_COMMAND_PROCESS_INFO)       ;
        MYSQL_CMD(MYSQL_COMMAND_PROCESS_KILL)       ;
        MYSQL_CMD(MYSQL_COMMAND_PING)               ;
        MYSQL_CMD(MYSQL_COMMAND_DELAYED_INSERT)     ;
        MYSQL_CMD(MYSQL_COMMAND_BINLOG_DUMP)        ;
        MYSQL_CMD(MYSQL_COMMAND_CONNECT_OUT)        ;
        MYSQL_CMD(MYSQL_COMMAND_STMT_PREPARE)       ;
        MYSQL_CMD(MYSQL_COMMAND_STMT_SEND_LONG_DATA);
        MYSQL_CMD(MYSQL_COMMAND_STMT_RESET)         ;
        MYSQL_CMD(MYSQL_COMMAND_STMT_FETCH)         ;
        MYSQL_CMD(MYSQL_COMMAND_BINLOG_DUMP_GTID)   ;
        MYSQL_CMD(MYSQL_COMMAND_LOGIN)              ;
        MYSQL_CMD(MYSQL_COMMAND_PENDING)            ;
        MYSQL_CMD(MYSQL_COMMAND_DO_NOT_EXIST)       ;
        MYSQL_CMD(MYSQL_COMMAND_QUIT)               ;
        MYSQL_CMD(MYSQL_COMMAND_QUERY)              ;
        MYSQL_CMD(MYSQL_COMMAND_CREATE_DB)          ;
        MYSQL_CMD(MYSQL_COMMAND_REFRESH)            ;
        MYSQL_CMD(MYSQL_COMMAND_STATISTICS)         ;
        MYSQL_CMD(MYSQL_COMMAND_CONNECT)            ;
        MYSQL_CMD(MYSQL_COMMAND_DEBUG)              ;
        MYSQL_CMD(MYSQL_COMMAND_TIME)               ;
        MYSQL_CMD(MYSQL_COMMAND_CHANGE_USER)        ;
        MYSQL_CMD(MYSQL_COMMAND_TABLE_DUMP)         ;
        MYSQL_CMD(MYSQL_COMMAND_REGISTER_SLAVE)     ;
        MYSQL_CMD(MYSQL_COMMAND_STMT_EXECUTE)       ;
        MYSQL_CMD(MYSQL_COMMAND_STMT_CLOSE)         ;
        MYSQL_CMD(MYSQL_COMMAND_SET_OPTION)         ;
        MYSQL_CMD(MYSQL_COMMAND_DAEMON)             ;
        MYSQL_CMD(MYSQL_COMMAND_RESET_CONNECTION)   ;
    }

    return "MYSQL_COMMAND_UNKNOWN";
}

void *MysqlGetTx(void *alstate, uint64_t tx_id) {
    MysqlState *s = alstate;
    MysqlTransaction *tx = NULL;
    if (s->cur_tx && s->tx_num == tx_id + 1) {
        tx = s->cur_tx;
        goto end;
    }

    /* TODO: we need to define the `get tx` logic according in
     * Mysql context, here we just return the tx with tx_id + 1 == tx_num,
     * and this may be not the correct one, sometimes we may need some
     * other tx(s) */
    TAILQ_FOREACH(tx, &s->tx_list, next) {
        SCLogDebug("s->tx_num %u, tx_id %"PRIu64, s->tx_num, (tx_id + 1));
        if (tx_id != tx->tx_id)
            continue;
        SCLogDebug("returning tx %p", tx);
        goto end;
    }
    return NULL;

end:
    return tx;
}

uint64_t MysqlGetTxCnt(void *alstate) {
    MysqlState *s = alstate;
    return (uint64_t) s->tx_num; /* current tx marked the total tx count */
}

void MysqlStateTxFree(void *state, uint64_t tx_id) {
    SCEnter();
    MysqlState *s = state;
    MysqlTransaction *tx = NULL;

    SCLogDebug("state %p, id %"PRIu64, s, tx_id);

    TAILQ_FOREACH(tx, &s->tx_list, next) {
        SCLogDebug("tx %p s->tx_num %u, tx_id %"PRIu64, tx, s->tx_num, (tx_id + 1));
        if (tx_id + 1 < s->tx_num)
            break;
        else if (tx_id + 1 > s->tx_num)
            continue;

        if (tx == s->cur_tx)
            s->cur_tx = NULL;
    }

    TAILQ_REMOVE(&s->tx_list, tx, next);
    MysqlTransactionFree(tx);
}

int MysqlGetAlstateProgressCompletionStatus(uint8_t dir) {
    return TRUE;
}

int MysqlGetAlstateProgress(void *tx, uint8_t direction) {
    (void) direction;
    MysqlTransaction *mysql_tx = tx;
    if (direction == 1)
        return mysql_tx->replied | mysql_tx->reply_lost;
    else
        /* FIXME: there is no pendding transection, but I dont know why
         * the `!=` here */
        return mysql_tx->s->pending == FALSE; 
}
