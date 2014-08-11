/*
 * Oracle 11g implementation
 * author: coanor <coanor@gmail.com>
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

static void CleanConnectData(Oracle11gState *s) {
    if (!s || !s->conn_data)
        return;

    if (s->conn_data->sid           ) SCFree(s->conn_data->sid           );
    if (s->conn_data->client_program) SCFree(s->conn_data->client_program);
    if (s->conn_data->client_host   ) SCFree(s->conn_data->client_host   );
    if (s->conn_data->user          ) SCFree(s->conn_data->user          );
    if (s->conn_data->protocol      ) SCFree(s->conn_data->protocol      );
    if (s->conn_data->server_host   ) SCFree(s->conn_data->server_host   );
    if (s->conn_data->server_port   ) SCFree(s->conn_data->server_port   );
    SCFree(s->conn_data);
    s->conn_data = NULL;
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

        CleanConnectData(s);
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
ParseOracle11gConnectData(const uint8_t *data, const uint16_t len) {
    if (unlikely(!data))
        return NULL;

    const uint8_t *p = data, *q = NULL;
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
            if (strncmp((const char *)q, "CID", 3) == 0)
                under_cid = 1;

            if (strncmp((const char *)q, "SID", 3) == 0
                    || strncmp((const char *)q, "PROGRAM", 7) == 0
                    || strncmp((const char *)q, "HOST", 4) == 0
                    || strncmp((const char *)q, "USER", 4) == 0
                    || strncmp((const char *)q, "PROTOCOL", 8) == 0
                    || strncmp((const char *)q, "PORT", 4) == 0) {
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

static int CaptrueSQL(Oracle11gState *s, Oracle11gTransaction *tx, uint8_t *payload) {
    uint8_t *p = payload;

    p = p + 68; /* skip to SQL length */

    uint8_t *sql = NULL;
    uint16_t sql_len = 0;

    if (*p == 0xfe && *(p + 1) == 0xff) {
        /* we can NOT use the length hint to get the
         * sql, the SQL payload looks like this:
         * 
         *   0xfe 0xff   ........... sep ........... sep ...........\0
         * |<indicator>| |<- 255 ->|     |<- 255 ->|     |<- 255 ->|
         *
         *
         * from above ascii art, we know that for a long SQL statement(0,2499),
         * each 255 bytes are separated by `sep', so we MUST skip this byte
         * to get the right SQL statement(note the last `\0').
         *
         * after several tests, we find that the `sep' byte are not constant,
         * sometimes it is 0x80, sometimes others, the 0x80 case cause
         * json_string() fail to load the SQL, but some printable bytes (i.e, `S'
         * or `<') are possible to be the seprator we must see this is a
         * pitfall of Oracle TNS protocol.
         */

        p += 2; /* skip indicator */

        int total_len = strlen((char *)p);
        sql = SCCalloc(total_len + 1, 1); /* maybe larger than real size */
        if (total_len > 255) {
            int idx = 0;
            int sep_cnt = total_len/256;

            tx->sql_len = total_len - sep_cnt;

            for (idx = 0; idx < sep_cnt; ++idx)
                memcpy(sql + idx * 255, /* only copy 255 bytes */
                        p + idx * 256, /* but offset 256 to skip the 0x80 */
                        255);

            /* N seprator can seprate N+1 part and we copy the remaining bytes */
            strcpy((char *)sql + sep_cnt * 255, (char *)p + sep_cnt * 256);
        } else { /* 255 bytes SQL do not seprated */
            strncpy((char *)sql, (char *)p, 255);
        }
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
    Oracle11gTransaction *tx = InsertOracleTx(s);
    /* all pkt before login ok are login pkt,
       no matter what it contains */
    if (!s->login_ok)
        tx->tx_type = oracle11g_tx_type_try_login;

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
        /* fall throwgh */
    case 0x03:
        ++p;
        switch (*p) {
        case 0x5e: /* query */
            ++p;
            tx->tx_type = oracle11g_tx_type_sql_query;
            if (!s->login_ok) {
                /* should we capture SQLs during login? */
                CaptrueSQL(s, tx, p);
            } else {
                CaptrueSQL(s, tx, p);
            }
            break;
        case 0x0e: /* commit */
            if (tx->tx_type == oracle11g_tx_type_try_login) {
                s->login_ok = TRUE;
            } else {
                ;/* TODO: anyother commit operation? */
            }
            break;
        case 0x52:
        case 0x53:
        case 0x73:
        case 0x76:
            tx->tx_type = oracle11g_tx_type_try_login;
            break;
        case 0x09:
            tx->tx_type = oracle11g_tx_type_disconnect;
            break;
        }
        break;
    default:
        break;
    }

#if 0
    /* do not need the SNS pkt, just skip it */
    uint32_t deadbeef = 0;
    ByteExtractUint32(&deadbeef, BYTE_BIG_ENDIAN, sizeof(uint32_t), payload);
    if (deadbeef == 0xdeadbeef) {
        ;/* SNS pkt, do nothing */
    }
#endif

    return 0;
}

static int Oracle11gParseLogin(Oracle11gState *s, uint8_t *in, uint32_t len) {
    uint16_t res;

    Oracle11gTransaction *tx = InsertOracleTx(s);
    tx->tx_type = oracle11g_tx_type_try_login;

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
    struct oracle11g_conn_data *conn_data = ParseOracle11gConnectData(connect_data, res);
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

#if 0
    if (in_len >= ORACLE_MAX_SQL_LEN)
        /* TODO: we should log it or trigger some event */
        return 0;
#endif

    Oracle11gState *s = alstate;
    int ret = ParseOracle11gHeader(&s->hdr, in, in_len);
    if (ret) {
        /* FIXME: on incomplete packets, we let them go, pretent to
           be nothing on this packet, this is OK because we can not
           process it */
        SCReturnInt(0);
    }

    /*  TODO: incomplete or maybe invalid packet */   
    if (s->hdr.pkt_len > in_len) {
        return 0; /* for invalid length, we pass it */
    }

    switch (s->hdr.pkt_type) {
        case TNS_CONNECT:
            if (!s->conn_data) {
                Oracle11gParseLogin(s, in, in_len);
            } else {
                /* duplicated login data, we drop previously connect
                 * data, and we should log it */
                CleanConnectData(s);
                Oracle11gParseLogin(s, in, in_len);
            }
            break;
        case TNS_DATA:
            Oracle11gParseData(s, in + 10, in_len - 10);
            break;
        default:
            SCLogDebug("not using pkt type %d", s->hdr.pkt_type);
            break;
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
    (void) dir;
    return TRUE;
}

int Oracle11gGetAlstateProgress(void *tx, uint8_t dir) {
    (void) tx;
    (void) dir;
    return TRUE;
}
