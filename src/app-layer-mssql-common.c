/**
 * author: coanor <coanor@gmail.com>
 * date: Tue Jun 10 10:10:29 CST 2014
 */
#include "app-layer-mssql-common.h"
#define TDS_HEADER_LEN 8

static int TDSTryParseHeader(TDSHeader *h, uint8_t *in, uint32_t len) {
    uint8_t *p = in;
    uint16_t res = 0;

    h->type = *p;
    ++p;
    h->status = *p;
    ++p;

    h->len = (*p * 256) + *(p + 1); /* first_byte * 256 + second_byte */
    p += 2;

    if (h->len < (uint16_t)len) {
        /* TODO: we simply validate the header, if not a header,
         * we parse fail, and we should make more strong check
         * on header validity */
        SCReturnInt(-1);
    }

    if (ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    h->channel = res;
    p += 2;
    h->pkt_number = *p;
    ++p;
    h->window = *p;
    return 0;
}

static int TDSPendingPkt(TDSState *s, uint8_t *in, uint32_t in_len) {
    if (!in || in_len <= 0)
        return 0;

    s->pending = TRUE;

    /* XXX: payload_size never include the header bytes,
     * on each pending pkt, the header is still in the pkt,
     * we must skip them */
    s->payload_size += in_len; 

    s->payload_bytes = SCRealloc(s->payload_bytes, s->payload_size);
    if (unlikely(!s->payload_bytes))
        SCReturnInt(-1);

    memcpy(s->payload_bytes + s->cur_payload_size, in, in_len);
    s->cur_payload_size += in_len; 
    return 0;
}

static void TDSCleanPending(TDSState *s) {
    if (!s || !s->payload_bytes)
        return;

    SCFree(s->payload_bytes);
    s->payload_bytes = NULL;
    s->pending = FALSE;
    s->cur_payload_size = 0;
    s->payload_size = 0;
}

static void TDSCleanClient(TDSClient *cli) {
    if (!cli)
        return;
    
    if (cli->client_name ) SCFree(cli->client_name  );
    if (cli->user_name   ) SCFree(cli->user_name    );
    if (cli->app_name    ) SCFree(cli->app_name     );
    if (cli->server_name ) SCFree(cli->server_name  );
    if (cli->library_name) SCFree(cli->library_name );
    if (cli->local       ) SCFree(cli->local        );
    if (cli->db_name     ) SCFree(cli->db_name      );
}

/*
 * for TDS protocol, characters are unicode encoded,
 * if @src only ascii characters, the len is double
 * of strlen(@src), so we must extract them as pure
 * ascii code.
 *
 * if there is some unicode chinese or some else,
 * we copy them as original
 *
 */
static uint8_t *TDSCopyPayload(uint8_t *src, uint32_t len) { 
    uint32_t idx = 0;
    uint32_t real_len = 0;

    if (len == 0)
        return 0;

    /* pre-calculate the neccessary memory to
     * extract the real bytes? */
    while (idx < len) {
        if (src[idx] != '\0')
            ++real_len;
        ++idx;
    }

    uint8_t *dst = SCCalloc(real_len + 1, 1);

    uint8_t *p = src;
    idx = 0;
    uint32_t copy_bytes = 0;
    while (real_len > copy_bytes) {
        if (p[idx] != '\0') {
            dst[copy_bytes++] = p[idx];
        }
        idx++;
    }

    return dst;
}

static int TDSExtractField(uint8_t **dst, uint8_t *pos, uint8_t *in, uint32_t pl) {
    uint16_t offset, len;
    uint8_t *p = in;

    if (ByteExtractUint16(&offset, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);

    p += 2;

    if (ByteExtractUint16(&len, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);

    if (len == 0 || offset == 0)
        SCReturnInt(0);

    if (offset + len >= pl)
        SCReturnInt(-1);

    *dst = TDSCopyPayload(pos + offset, len * 2);

    return 0;
}

static int TDSVer7ParseLogin(TDSState *s, uint8_t *in, uint32_t len) {
    uint8_t *p = in;
    uint8_t *q = NULL;

    if ((uint16_t)len < s->hdr.len)
        SCReturnInt(-1); /* should not happen */

    p += TDS_HEADER_LEN; /* skip header */
    q = p;

    struct tds7_login_pkt {
        uint32_t total_pkt_len,
                 tds_ver,
                 pkt_size,
                 cli_ver,
                 cli_pid,
                 conn_id;
        uint8_t flag1,
                flag2,
                sql_type_flag,
                reserved_flag;
        uint32_t time_zone,
                 collation;
    } login_pkt;

    if (ByteExtractUint32(&login_pkt.total_pkt_len, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.tds_ver, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.pkt_size, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.cli_ver, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.cli_pid, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.conn_id, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */

    login_pkt.flag1 = *p++;
    login_pkt.flag2 = *p++;
    login_pkt.sql_type_flag = *p++;
    login_pkt.reserved_flag = *p++;

    if (ByteExtractUint32(&login_pkt.time_zone, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */
    if (ByteExtractUint32(&login_pkt.collation, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4; /* tds version */

    s->cur_tx->tds_version = login_pkt.tds_ver;
    
    TDSClient *cli = &s->cli;
    uint32_t payload_len = s->hdr.len - TDS_HEADER_LEN;
    if (TDSExtractField(&cli->client_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->user_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->password, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->app_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->server_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    p += 4; /* skip unknown field */

    if (TDSExtractField(&cli->library_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->local, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (TDSExtractField(&cli->db_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    s->cur_tx->tx_type = tds_tx_type_login;

    return 0;

error:
    TDSCleanClient(&s->cli);
    return -1;
}

static TDSTransaction *TDSInsertTx(TDSState *s) {
    TDSTransaction *tx = SCCalloc(sizeof(*tx), 1);
    if (unlikely(!tx)) {
        SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc error in Oracle11gTransaction");
        return NULL;
    }

    tx->s = s;
    if (!s->cur_tx)
        tx->tx_id = 0; /* first tx on the state */
    else
        tx->tx_id = s->cur_tx->tx_id + 1;

    s->cur_tx = tx;
    TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    ++s->tx_num;
    return tx;
}

static int TDSCaptureSql(TDSState *s, TDSTransaction *tx) {
    if (!s->pending) {
        tx->sql_len = s->cur_pkt_len - TDS_HEADER_LEN;
        tx->sql = TDSCopyPayload(s->cur_pkt + TDS_HEADER_LEN, tx->sql_len);
    } else {
        tx->sql_len = s->payload_size;
        tx->sql = TDSCopyPayload(s->payload_bytes, tx->sql_len);
    }

    s->cur_tx->tx_type = tds_tx_type_query;

    return 0;
}

int TDSParseClientRecord(Flow *f, void *alstate,
		AppLayerParserState *pstate,
		uint8_t *in, uint32_t len, void *local_data) {

    (void) pstate;

    TDSState *s = alstate;
    if (!s)
        SCReturnInt(-1);

    int ret = 0;
    TDSTransaction *tx = NULL;
    uint8_t *p = NULL;
    (void) p; /* silence warnning */

    s->cur_pkt = in;
    s->cur_pkt_len = len;

    ret = TDSTryParseHeader(&s->hdr, in, len);
    if (ret) {
        /* FIXME: for incomplete packet, how to handle it?
         * currently we do nothing to keep original traffic */ 
        SCReturnInt(0);
    }

    if (TDS_EOM(&s->hdr)) {
        if (s->pending)
            TDSPendingPkt(s, in + TDS_HEADER_LEN, len - TDS_HEADER_LEN);   
        goto complete_pkt;
    } else {
        TDSPendingPkt(s, in + TDS_HEADER_LEN, len - TDS_HEADER_LEN);
        SCReturnInt(0);
    }

complete_pkt:

    tx = TDSInsertTx(s);
    if (unlikely(!tx))
        SCReturnInt(-1);

    if (s->pending) {
        p = s->payload_bytes;   
    } else {
        p = in;
    }

    switch (s->hdr.type) {
    case TDS_SQL_BATCH:
         TDSCaptureSql(s, tx);

         ret = 0;
         break;

    case TDS7_LOGIN:
         ret = TDSVer7ParseLogin(s, in, len);
         break;

         /* TODO */
    case TDS_LOGIN:
    case TDS_RPC       :
    case TDS_REPLY     :
    case TDS_CANCEL    :
    case TDS_BULK      :
    case TDS_NORMAL    :
    case TDS_AUTH      :
    case TDS_PRELOGIN  :
         break;
    }

    if (s->pending)
        TDSCleanPending(s);

    return ret;
}

int TDSParseServerRecord(Flow *f, void *alstate,
		AppLayerParserState *pstate,
		uint8_t *in, uint32_t len, void *local_data) {
    TDSState *s = alstate;
    if (!s)
        SCReturnInt(-1);
    return 0; /* ignore server response */
}

static void TDSTransactionFree(TDSTransaction *tx) {
    if (tx->sql) 
        SCFree(tx->sql);
    SCFree(tx);
}

void TDSStateFree(void *state) {
    TDSState *s = (TDSState *)state;
    if (s) {
        TDSTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&s->tx_list))) {
            TAILQ_REMOVE(&s->tx_list, tx, next);
            TDSTransactionFree(tx);
        }
    }
}

void *TDSStateAlloc(void) {
    TDSState *s = SCCalloc(sizeof(*s), 1);
    if (unlikely(!s))
        return NULL;
    TAILQ_INIT(&s->tx_list);
    return s;
}

int TDSRequestParse(uint8_t *in, uint32_t len) {
    /* do nothing */
    return 0;
}

void *TDSGetTx(void *alstate, uint64_t tx_id) {
    TDSState *s = alstate;
    if (s->cur_tx->tx_id == tx_id)
        return s->cur_tx;

    TDSTransaction *tx = NULL;    
    TAILQ_FOREACH(tx, &s->tx_list, next) {
        if (tx->tx_id == tx_id)
            return tx;
    }

    return NULL;
}

uint64_t TDSGetTxCnt(void *alstate) {
    TDSState *s = alstate;
    return s->tx_num;
}

int TDSGetAlstateProgressCompletionStatus(uint8_t dir) {
    return TRUE;
}

int TDSGetAlstateProgress(void *tx, uint8_t dir) {
    TDSTransaction *tds_tx = tx;
    return (tds_tx->s->payload_bytes == NULL);
}
