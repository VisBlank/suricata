/**
 * \file
 * \author
 *
 * MySQL related features to release burden on app-layer-mysql
 */

#include "app-layer-mysql-common.h"

#define MYSQL_HDR_LEN 4

void *MysqlTransactionAlloc(const uint16_t tx_id);

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
        tx = MysqlTransactionAlloc(conn_id);
        s->cur_tx = tx;
        TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    }

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
    PendingPkt *ppkt, *cur_ppkt = state->cur_tx->cur_ppkt;

    switch (res) {
        case PKT_COMPLETE:
            return ParseCompleteMysqlClientPkt(state, input, input_len);
        case PKT_INCOMPLETE_WITH_HEAD:
            if (cur_ppkt) {
                /* drop old one */
                cur_ppkt->flags = PPKT_DROP;
                ppkt = SCMalloc(sizeof(*ppkt));
                if (unlikely(ppkt == NULL)) {
                    /* we should set some info to the transaction */
                    return -1;
                }
                TAILQ_INSERT_HEAD(&state->cur_tx->ppkt_list, ppkt, next);
                state->cur_tx->cur_ppkt = ppkt;
                SCLogDebug("new ppkt %p", ppkt);
            }

            if (InitPendingPkt(ppkt, input, input_len) == -1) {
                /* TODO: drop */
                return -1;
            }
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
    void *s = SCMalloc(sizeof(MysqlState));
    if (s == NULL)
        return NULL;
    memset(s, 0, sizeof(MysqlState));

    MysqlState *mysql_state = (MysqlState *)s;
    TAILQ_INIT(&mysql_state->tx_list);
    return s;
}

void MysqlStateClean(MysqlState *ms) {
    /* TODO */
}

void *MysqlTransactionAlloc(const uint16_t tx_id) {
    (void) tx_id;
    MysqlTransaction *tx = SCMalloc(sizeof(MysqlTransaction));
    if (unlikely(tx == NULL))
        return NULL;
    memset(tx, 0, sizeof(*tx));
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
