/*
 * Oracle 11g implementation
 * author: tanb <tanb@titansec.com.com>
 * date: Fri Mar 28 14:34:15 CST 2014
 */

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "queue.h"
#include "app-layer-oracle11g-common.h"

enum tns_pkt_type {
    TNS_CONNECT = 0x01,
    TNS_ACCEPT = 0x02,
    TNS_REFUSE = 0x04,
    TNS_REDIRECT = 0x05,
    TNS_DATA = 0x06,
    TNS_RESEND = 0xb,
    TNS_MARKER = 0xc,
    TNS_ATTENTION = 0xd,
    TNS_CONTROL = 0xe,
};

void *Oracle11gStateAlloc(void) {
    Oracle11gState *s = SCCalloc(sizeof(*s), 1);
    if (unlikely(s == NULL))
        return NULL;
    TAILQ_INIT(&s->tx_list);
    return s;
}

static void Oracle11gTransactionFree(Oracle11gTransaction *tx) {
    if (tx) {
        SCFree(tx->sql);
        SCFree(tx);
    }
}

void Oracle11gStateFree(void *state) {
    SCEnter();
    Oracle11gState *s = state;
    if (s) {
        Oracle11gTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&s->tx_list))) {
            TAILQ_REMOVE(&s->tx_list, tx, next);
            Oracle11gTransactionFree(tx);
        }

        if (s->pending_bytes)
            SCFree(s->pending_bytes);
        SCFree(s);
    }
}

static int ParseOracle11gHeader(Oracle11gHeader *hdr, uint8_t *in, uint32_t in_len) {
    if (in_len < ORACLE11G_HEADER_SIZE)
        SCReturnInt(-1);

    uint16_t res;
    int ret = ByteExtractUint16(&res, BYTE_BIG_ENDIAN, sizeof(uint16_t), in);

    if (ret <= 0)
        SCReturnInt(-1);
    if (res < in_len - ORACLE11G_HEADER_SIZE)
        SCReturnInt(-1);

    hdr->pkt_len = res;

    hdr->pkt_type = in[4];
    SCReturnInt(0);
}

static struct oracle11g_conn_data *
ParseOracle11gConnectData(Oracle11gState *s, const uint8_t * const data, const uint16_t len) {
    if (unlikely(!data))
        return NULL;

    uint8_t *p = data, *q = NULL;
    char *cur_key = NULL, *cur_val = NULL;
    int got_val = 0, got_key = 0, under_cid = 0;

    struct oracle11g_conn_data *conn_data = SCCalloc(sizeof(*conn_data), 1);
    if (unlikely(!conn_data)) {
        SCLogError(SC_ERR_MEM_ALLOC, "scalloc fail on parsing oracle connect data");
        goto fail;
    }

    while (1) {
        if (*p == '\0')
            break;
        switch (*p) {
        case '(':
            q = p + 1; /* new key */
            break;
        case ')': /* end of value */
            got_val = 1;
            break;
        case '=':
            got_key = 1;
            break;
        default:
            break;
        }

        if (got_key) {
            if (strncmp(q, "CID", 3) == 0)
                under_cid = 1;

            if (strncmp(q, "SID", 3) == 0
                    || strncmp(q, "PROGRAM", 7) == 0
                    || strncmp(q, "HOST", 4) == 0
                    || strncmp(q, "USER", 4) == 0
                    || strncmp(q, "PROTOCOL", 8) == 0
                    || strncmp(q, "PORT", 4) == 0) {
                /* we only need these keys */
                cur_key = SCCalloc(p - q + 1, 1);
                if (unlikely(!cur_key)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "scalloc fail on parsing oracle connect data");
                    goto fail;
                }
                memcpy(cur_key, q, p - q);

            }
            q = p + 1; /* q skip the `=` byte */
            got_key = 0;
        }

        if (got_val) {
            if (cur_key) {
                cur_val = SCCalloc(p - q + 1, 1);
                if (unlikely(!cur_val)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "scalloc fail on parsing oracle connect data");
                    goto fail;
                }

                memcpy(cur_val, q, p - q);
                if (strncmp(cur_key, "SID", 3) == 0)
                    conn_data->sid = cur_val;
                else if (strncmp(cur_key, "PROGRAM", 7) == 0)
                    conn_data->client_program = cur_val;
                else if (strncmp(cur_key, "HOST", 4) == 0) {
                    if (under_cid) { /* client host */
                        conn_data->client_host = cur_val;
                        under_cid = 0;
                    } else
                        conn_data->server_host = cur_val;
                } else if (strncmp(cur_key, "USER", 4) == 0)
                    conn_data->user = cur_val;
                else if (strncmp(cur_key, "PROTOCOL", 8) == 0)
                    conn_data->protocol = cur_val;
                else if (strncmp(cur_key, "PORT", 4) == 0)
                    conn_data->server_port = cur_val;

                cur_val = NULL;
                SCFree(cur_key);
                cur_key = NULL;
            }
            q = p + 1; /* skip ')' byte */
            got_val = 0;
        }
        ++p;
    }

    return (conn_data);

fail:
    if (cur_val)
        SCFree(cur_val);

    if (cur_key)
        SCFree(cur_key);

    if (conn_data)
        SCFree(conn_data);

    return (NULL);
}

static Oracle11gTransaction *InsertOracleTx(Oracle11gState *s) {
    Oracle11gTransaction *tx = SCCalloc(sizeof(*tx), 1);
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

static int CaptrueSQL(uint8_t *payload, Oracle11gState *s, Oracle11gTransaction *tx) {
    uint8_t *p = payload;

    p = p + 68; /* skip to SQL length */

    uint8_t *sql = NULL;
    uint16_t sql_len = 0;

    if (*p == 0xfe && *(p + 1) == 0xff) {
        /* we can NOT use the length hint to get the
         * sql, we find it just a placeholder */
        sql = SCStrdup((char *)(p + 2));
        tx->sql_len = strlen((const char *)sql);
    } else {
        if (*p == 0xfe && *(p + 1) < 0xff)
            sql_len = *(p + 1);
        else
            sql_len = *p;

        sql = SCCalloc(sql_len + 1, 1);
        if (unlikely(!sql)) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc error in Oracle11gParseData");
            SCReturnInt(-1);
        }
        memcpy(sql, p + 1, sql_len);
        tx->sql_len = sql_len;
    }
    tx->sql = sql;
    return 0;
}

static int Oracle11gParseData(Oracle11gState *s, uint8_t *payload, uint32_t len) {
    uint8_t *p = payload;
    if (unlikely(!p)) {
        SCLogDebug("empty payload data");
        SCReturnInt(-1);
    }
    
    /* only insert tx on specific case */
    Oracle11gTransaction *tx = NULL;

    switch (*p) {
    case 0x01:
    case 0x02:
        break;
    case 0x11:
        if (p[1] == 0x69) {
            p += 2;
            /* client's `cursor close all operation' */
            ++p; /* skip sequence */
            p += 9; /* direct skip to 0x035e */
        }
        /* fall thru */
    case 0x03:
        ++p;
        switch (*p) {
        case 0x5e: /* query */
            ++p;
            tx = InsertOracleTx(s);
            tx->tx_type = oracle11g_tx_type_sql_query;
            if (!s->login_ok) {
                /* should we capture SQLs during login? */
                CaptrueSQL(p, s, tx);
            } else {
                CaptrueSQL(p, s, tx);
            }
            break;
        case 0x0e: /* commit */
            tx = InsertOracleTx(s);
            if (s->cur_tx->tx_type == oracle11g_tx_type_try_login && !s->login_ok) {
                s->login_ok = TRUE;
            } else {
                ;/* TODO: anyother commit operation? */
            }
            break;
        case 0x52:
        case 0x53:
        case 0x73:
        case 0x76:
            tx = InsertOracleTx(s);
            s->cur_tx->tx_type = oracle11g_tx_type_try_login;
            break;
        case 0x09:
            tx = InsertOracleTx(s);
            s->cur_tx->tx_type = oracle11g_tx_type_disconnect;
            break;
        }
        break;
    default:
        break;
    }

    uint32_t deadbeef = 0;
    int ret = ByteExtractUint32(&deadbeef, BYTE_BIG_ENDIAN, sizeof(uint32_t), payload);
    if (deadbeef == 0xdeadbeef) {
        ;/* SNS pkt, do nothing */
    }
}

static int pending(Oracle11gState *s, uint8_t *in, uint32_t in_len) {
    if (!in || in_len <= 0)
        return 0;

    if (s->pending_size + in_len > s->expected_size) {
        /* clean pending data */
        SCFree(s->pending_bytes);
        s->pending = 0;
        return 0;
    }

    s->pending_bytes = SCRealloc(s->pending_bytes, s->pending_size + in_len);
    memcpy(s->pending_bytes + s->pending_size, in, in_len);
    s->pending_size += in_len; 

    if (s->pending_size == s->expected_size) {
        s->pending = 0;
    }
}

static int Oracle11gParseLogin(Oracle11gState *s, uint8_t *in, uint32_t len) {
    uint16_t res;

    Oracle11gTransaction *tx = InsertOracleTx(s);

    /* protocol version encoded in big endian after the payload type byte */
    int ret = ByteExtractUint16(&res, BYTE_BIG_ENDIAN, sizeof(uint16_t), in + ORACLE11G_HEADER_SIZE);
    if (!ret)
        SCReturnInt(-1);
    s->protocol_version = res;

    ret = ByteExtractUint16(&res, BYTE_BIG_ENDIAN, sizeof(uint16_t), in + ORACLE11G_HEADER_SIZE + 2);
    if (!ret)
        SCReturnInt(-1);
    s->compatible_version = res;

    /* connect data length */
    ret = ByteExtractUint16(&res, BYTE_BIG_ENDIAN, sizeof(uint16_t), in + ORACLE11G_HEADER_SIZE + 16);
    if (!ret)
        SCReturnInt(-1);
    int data_len = res;

    ret = ByteExtractUint16(&res, BYTE_BIG_ENDIAN, sizeof(uint16_t), in + ORACLE11G_HEADER_SIZE + 18);
    if (!ret)
        SCReturnInt(-1);
    int offset = res;

    uint8_t *connect_data = SCCalloc(data_len + 1, 1);
    memcpy(connect_data, in + offset, data_len);
    struct oracle11g_conn_data *conn_data = ParseOracle11gConnectData(s, connect_data, res);
    if (unlikely(!conn_data)) {
        SCReturnInt(-1);
    }
    s->conn_data = conn_data;
    SCReturnInt(0);
}

int Oracle11gParseServerRecord(Flow *f, void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data) {
    if (in_len < ORACLE11G_HEADER_SIZE)
        return -1;

    Oracle11gState *s = alstate;
    Oracle11gHeader hdr;
    int ret = ParseOracle11gHeader(&hdr, in, in_len);
    if (ret) {
        /* FIXME: we also let the packet go, do nothing on it */
        SCReturnInt(0);
    }

    switch (hdr.pkt_type) {
        case TNS_ACCEPT:
            /* just accept, not login ok, server may reject the client */
            break;
        case TNS_DATA:
            break; /* do not parse server side data response */
        case TNS_RESEND:
            s->resend = TRUE;
            break;
        case TNS_MARKER:
            s->marker = TRUE;
            break;
        case TNS_ATTENTION:
            break;
    }

    return 0;
}

int Oracle11gParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data) {
    if (in_len < ORACLE11G_HEADER_SIZE)
        return -1;

    Oracle11gState *s = alstate;
    if (!s->pending) {
        int ret = ParseOracle11gHeader(&s->hdr, in, in_len);
        if (ret) {
            /* FIXME: on incomplete packets, we let them go, pretent to
               be nothing on this packet, this is OK because we can not
               process it */
            SCReturnInt(0);
        }

        printf("pkt_len: %d, in_len: %d", s->hdr.pkt_len, in_len);

        /*  TODO: incomplete or maybe invalid packet */   
        if (s->hdr.pkt_len > in_len) {
            s->pending = 1;
            s->expected_size = s->hdr.pkt_len;
        }
    }

    if (s->pending) {
        /* pending packages */
        pending(s, in, in_len);
        if (!s->pending && s->pending_bytes != NULL) {
            in = s->pending_bytes;
            in_len = s->pending_size;
        } else {
            return 0;
        }
    }

    switch (s->hdr.pkt_type) {
        case TNS_CONNECT:
            Oracle11gParseLogin(s, in, in_len);
            break;
        case TNS_DATA:
            Oracle11gParseData(s, in + 10, in_len - 10);
            break;
        default:
            SCLogDebug("not using pkt type %d", s->hdr.pkt_type);
            break;
    }

    if (!s->pending && s->pending_bytes != NULL) {
        SCFree(s->pending_bytes);
        s->pending_bytes = NULL;
        s->expected_size = 0;
    }

    SCReturnInt(0);
}

void *Oracle11gGetTx(void *alstate, uint64_t tx_id) {
    Oracle11gState *s = alstate;
    Oracle11gTransaction *tx = NULL;
    if (s->cur_tx && s->tx_num == tx_id + 1) {
        tx = s->cur_tx;
        goto end;
    }

    TAILQ_FOREACH(tx, &s->tx_list, next) {
        if (tx_id == tx->tx_id)
            goto end;
    }

    return NULL; /* no tx with tx_id find */

end:
    if (tx->logged)
        return NULL;
    return tx;
}

uint64_t Oracle11gGetTxCnt(void *alstate) {
    Oracle11gState *s = alstate;
    return s->tx_num;
}

int Oracle11gGetAlstateProgressCompletionStatus(uint8_t dir) {
    return 0;
}

int Oracle11gGetAlstateProgress(void *tx, uint8_t dir) {
    Oracle11gTransaction *otx = tx;

    /* if there is no data pending, we suppose it was complete */
    return otx->s->pending_bytes == NULL;
}
