#ifndef __APP_LAYER_TDS_COMMON_H__
#define __APP_LAYER_TDS_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

int TDSRequestParse(uint8_t *input, uint32_t ilen);

void TDSStateFree(void *ms);
void *TDSStateAlloc(void);
const uint8_t *TDSCmdStr(size_t cmd);

enum pkt_status {
    /* bit 0~4 */
    END_OF_MSG = 1,
    IGNORE_THIS_EVENT = 2,
    EVENT_NOTIFICATION = 4,
    RESET_CONNECTION = 8,
    RESET_CONNECTION_KEEPING_TRANSACTION_STATE = 16,
};

enum tds_pkt_type {
    TDS_QUERY = 1,
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

typedef struct TDSPktHeader_ {
    char type;
    char status;
    short length; /* payload + head */
    short channel;
    char pkt_number;
    char window;
} TDSPktHeader;

typedef struct TDSClientCommand_ {
    int tds_cmd; /* no command list for TDS protocol */
    int sql_size;
    char *sql;
} TDSClientCommand;

typedef struct TDSClient_ {
    /* address not in use */
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    char *client_name;
    char *user_name;
    char *password; /* crypted, in hex bytes */
    char *app_name;
    char *server_name;
    char *library_name;
    char *locale;
    char *db_name;
} TDSClient;

typedef struct TDSTransaction_ {
    uint16_t tx_num;
    uint16_t tx_id;

    /* flags */
    uint8_t try_login;
    uint8_t login_ok;
    uint8_t wait_auth; /* wait SSPI message from client */

    uint8_t replied;
    uint8_t reply_lost;
    uint8_t reply_error; /* server say error or no on command */

    uint32_t tds_version;
#if 0
    TAILQ_HEAD(, PendingPkt_) ppkt_list;
    PendingPkt *cur_ppkt;
#endif

    TDSClientCommand cmd;

    TDSClient cli;

    /* need list to the next? */
    TAILQ_ENTRY(TDSTransaction_) next;
} TDSTransaction;

typedef struct TDSState_ {
    TAILQ_HEAD(, TDSTransaction_) tx_list;
    TDSTransaction *cur_tx;
    
    uint8_t *input;
    uint32_t input_len;
} TDSState;

#endif
