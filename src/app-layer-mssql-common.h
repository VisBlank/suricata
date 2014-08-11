#ifndef __APP_LAYER_MSSQL_COMMON_H__
#define __APP_LAYER_MSSQL_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "queue.h"

int TDSParseClientRecord(Flow *f, void *alstate,
		AppLayerParserState *pstate,
		uint8_t *in, uint32_t len, void *local_data);
int TDSParseServerRecord(Flow *f, void *alstate,
		AppLayerParserState *pstate,
		uint8_t *in, uint32_t len, void *local_data);

void TDSStateFree(void *state);
void *TDSStateAlloc(void);
int TDSRequestParse(uint8_t *in, uint32_t len);

void *TDSGetTx(void *alstate, uint64_t tx_id);
uint64_t TDSGetTxCnt(void *alstate);
int TDSGetAlstateProgressCompletionStatus(uint8_t dir);
int TDSGetAlstateProgress(void *tx, uint8_t dir);

enum tds_pkt_type {
    TDS_SQL_BATCH = 1,
    TDS_LOGIN = 2,
    TDS_RPC = 3,
    TDS_REPLY = 4,
    TDS_CANCEL = 6, /* attention */
    TDS_BULK = 7,   /* send binary data to server */
    TDS_NORMAL = 15,/* unused */
    TDS7_LOGIN = 16,
    TDS_AUTH = 17, /* FIXME */
    TDS_PRELOGIN = 18
};

typedef struct TDSClient_ {
    uint8_t *client_name;
    uint8_t *user_name;
    uint8_t *password;
    uint8_t *app_name;
    uint8_t *server_name;
    uint8_t *library_name;
    uint8_t *local;
    uint8_t *db_name;
} TDSClient;

typedef struct TDSState_ TDSState;
typedef struct TDSTransaction_ {
    TDSState *s;
    uint32_t tx_id;
    uint32_t tds_version;

    enum {
        tds_tx_type_unknown = 0,
        tds_tx_type_query = 1,
        tds_tx_type_login,
    } tx_type;

    uint8_t *sql;
    uint32_t sql_len;
    int action;
    TAILQ_ENTRY(TDSTransaction_) next;
} TDSTransaction;

/* end of message */
#define TDS_EOM(hdr) ((hdr)->status & 0x01)
/* ignore the message */
#define TDS_IGN(hdr) ((hdr)->status & 0x02)
/* event notification */
#define TDS_EVT_NOTIFY(hdr) ((hdr)->status & 0x04)
/* reset connection */
#define TDS_RST_CONNECT(hdr) ((hdr)->status & 0x08)
/* reset connection keeping tx state */
#define TDS_KEEP_TX(hdr) ((hdr)->status & 0x0f)

typedef struct TDSHeader_ {
    char type;
    char status;
    short len;
    short channel;
    char pkt_number;
    char window;
} TDSHeader;

struct TDSState_ {
   TDSHeader hdr;
   TAILQ_HEAD(, TDSTransaction_) tx_list;
   TDSTransaction *cur_tx;
   TDSClient cli;

   uint8_t *cur_pkt; /* reference to current pkt */
   uint32_t cur_pkt_len;

   uint8_t pending; /* to indicate that there was remaining bytes */
   uint8_t *payload_bytes;
   uint32_t cur_payload_size, payload_size;

   uint64_t tx_num;
};

#endif
