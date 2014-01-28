#ifndef __APP_LAYER_TNS_COMMON_H__
#define __APP_LAYER_TNS_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

enum tns_pkt_type {
    TNS_CONNECT = 1,
};

typedef struct TNSPktHeader_ {
    uint16_t length,
             chksum;
    uint8_t type,
            reserved;
    uint16_t hdr_chksum;
} TNSPktHeader;

typedef struct TNSTransaction_ {
    char *conn_data;

    uint8_t req_conn,
            resp_resend,
            resp_accept;
} TNSTransaction;

typedef struct TNSState_ {
    TAILQ_HEAD(, TNSTransaction_) tx_list;
    TNSTransaction *cur_tx;
    
    uint8_t *input;
    uint32_t input_len;
} TNSState;

#endif
