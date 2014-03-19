/**
 * \file
 * \auth: tanb <tanb@titansec.com.cn>
 * Mon Jan 27 10:26:05 CST 2014
 */
#include "app-layer-tds-common.h"
#include "util-byte.h"

#define TDS_HDR_LEN 8

static int ParseTNSPktHdr(TNSPktHeader *hdr, uint8_t *in, uint32_t len);
static int ParseTNSConnectPkt(TNSState *s, uint8_t *in, uint32_t len, TNSPktHeader *hdr);

int TDSParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data,
        AppLayerParserResult *output) {

    TNSState *s = alstate;
    SCEnter();

    if (!s)
        SCReturnInt(-1);

    if (!s->cur_tx) {
        TNSTransaction *tx = TNSTransactionAlloc();      
        if (!tx)
            return -1;
        s->cur_tx = tx;
        TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    }

    uint8_t *p = input;
    TNSPktHeader hdr;
    int ret;

    ret = ParseTNSPktHdr(&hdr, input, input_len);
    if (ret)
        SCReturnInt(-1);
    p += TNS_HDR_LEN;

    switch (hdr.type) {
        case TNS_CONNECT:
            ParseTNSConnectPkt(s, input, input_len, &hdr);
            break;
        default:break;
    }

    return 0;
}

static int ParseTNSConnectPkt(TNSState *s, uint8_t *in,
        uint32_t len, TNSPktHeader *hdr) {
    /*
     * @service_option:
     *    ____
     *    |15| 
     *    |14|
     *    |13| -> broken connect notify
     *    |12| -> pkt checksum
     *    |11| -> hdr checksum
     *    |10| -> full duplex
     *    |09| -> half duplex
     *    |08| -> don't care
     *    |07| -> don't care
     *    |06| -> 
     *    |05| ->
     *    |04| -> direct IO to transport
     *    |03| -> attention processing
     *    |02| -> can receive attention
     *    |01| -> can send attention
     *    |00|
     *    ----
     *
     * @nt_protocol_characters:
     *    ____
     *    |15| -> hangon to listener connec
     *    |14| -> confirmed release
     *    |13| -> TDU based IO
     *    |12| -> spawner running
     *    |11| -> data test
     *    |10| -> callback IO support
     *    |09| -> async IO support
     *    |08| -> packet oriented IO
     *    |07| -> can grant connection to another
     *    |06| -> can handoff connection to another
     *    |05| -> generate SIGIO signal
     *    |04| -> generate SIGPIPE signal
     *    |03| -> generate SIGURG signal
     *    |02| -> urgent IO support
     *    |01| -> full duplex IO support
     *    |00| -> test operation
     *    ----
     *
     * @conn_flag:
     *    ___
     *    |07| ->
     *    |06| ->
     *    |05| ->
     *    |04| -> NA service required
     *    |03| -> NA service linked in
     *    |02| -> NA service enabled
     *    |01| -> interchange is involved
     *    |00| -> NA service wanted
     *    ----
     */
    struct tns_conn_ {
        uint16_t version, version_compatible;
        short service_option;

        uint16_t session_data_unit_size,
                 max_transmission_data_unit_size;

        short nt_protocol_characters;
    
        uint16_t line_turnaround,
                 val_of_1_in_hardware,
                 length_of_connect_data,
                 offset_to_connect_data;
        uint32_t max_recv_conn_data;

        /* they seem the same value in wireshark */
        uint8_t conn_flag0, conn_flag1;
        
        uint32_t trace_cross_facility_item0,
                 trace_cross_facility_item1;
        uint64_t trace_unique_conn_id;
        char *conn_data;
    } conn;

    if (ByteExtractUint16(&conn.version, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.version_compatible, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16((uint16_t *)&conn.service_option, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.session_data_unit_size, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.max_transmission_data_unit_size, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16((uint16_t *)&conn.nt_protocol_characters, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.line_turnaround, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.val_of_1_in_hardware, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.length_of_connect_data, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint16(&conn.offset_to_connect_data, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint32(&conn.max_recv_conn_data, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    conn.conn_flag0 = *p;
    ++p;
    conn.conn_flag1 = *p;
    ++p;

    if (ByteExtractUint32(&conn.trace_cross_facility_item0, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    if (ByteExtractUint32(&conn.trace_cross_facility_item1, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    if (ByteExtractUint64(&conn.trace_unique_conn_id, BYTE_LITTLE_ENDIAN, 8, p) <= 0)
        SCReturnInt(-1);
    p += 8;

    conn.conn_data = SCCalloc(conn.length_of_connect_data + 1);
    if (conn.conn_data == NULL)
        SCReturnInt(-1);

    memcpy(conn.conn_data,
            input + conn.offset_to_connect_data,
            conn.length_of_connect_data);

    /* if we need the conn, just attach to @s */

    /* we may offer some parse on @conn_data to
       retrieve more info about the connection */
    s->conn_data = conn.conn_data;
    s->cur_tx->req_conn = 1;
    return 0;
}

static int ParseTNSPktHdr(TNSPktHeader *hdr, uint8_t *in, uint32_t len) {
    uint8_t *p = in;
    uint16_t res = 0;

    if (ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    hdr->length = res;
    p += 2;

    if (ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    hdr->chksum = res;
    p += 2;

    hdr->type = *p;
    ++p;
    hdr->reserved = *p;
    ++p;

    if (ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    hdr->hdr_chksum = res;

    return 0;
}
