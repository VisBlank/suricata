#ifndef __APP_LAYER_ORACLE11G_COMMON_H__
#define __APP_LAYER_ORACLE11G_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "queue.h"

#define ORACLE11G_HEADER_SIZE 8
#define ORACLE_MAX_SQL_LEN 2499

typedef struct Oracle11gHeader_ {
    uint16_t pkt_len,
             pkt_chksum,
             hdr_chksum;
    uint8_t pkt_type;
} Oracle11gHeader;

typedef struct Oracle11gState_ Oracle11gState;
typedef struct Oracle11gTransaction_ {
    Oracle11gState *s;
    uint16_t tx_id;

    /* transaction types */
    enum {
        oracle11g_tx_type_unknown = 0,
        oracle11g_tx_type_try_login,
        oracle11g_tx_type_sql_query,
        oracle11g_tx_type_disconnect
    } tx_type;

    uint8_t *sql;
    uint32_t sql_len;
    int action;
    uint8_t logged;
    TAILQ_ENTRY(Oracle11gTransaction_) next;
} Oracle11gTransaction;

struct oracle11g_conn_data {
    char *sid, *client_program, *client_host, *user, *protocol, *server_host, *server_port;
};

struct oracle11g_conn_data;
typedef struct Oracle11gState_ {
    Oracle11gHeader hdr;
    TAILQ_HEAD(, Oracle11gTransaction_) tx_list;
    Oracle11gTransaction *cur_tx;

    struct oracle11g_conn_data *conn_data;

    uint8_t *protocol_name;
    uint16_t protocol_version, compatible_version;
    
    uint8_t login_ok, logout,
            resend, marker;

    uint8_t last_seq;
    uint64_t tx_num;
} Oracle11gState;

int Oracle11gParseClientRecord(Flow *f, void *alstate, AppLayerParserState *alps,
        uint8_t *in, uint32_t in_len, void *local_data);

int Oracle11gParseServerRecord(Flow *f, void *alstate, AppLayerParserState *alps,
        uint8_t *in, uint32_t in_len, void *local_data);

void Oracle11gStateFree(void *ds);
void *Oracle11gStateAlloc(void);
void *Oracle11gGetTx(void *alstate, uint64_t tx_id);

uint64_t Oracle11gGetTxCnt(void *alstate);
int Oracle11gGetAlstateProgressCompletionStatus(uint8_t dir);
int Oracle11gGetAlstateProgress(void *tx, uint8_t dir);
#endif
