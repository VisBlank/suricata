/**
 * \file
 * \author
 * Mon Jan 20 14:09:46 CST 2014
 * common features for various TDS protocols
 */

#include "app-layer-tds-common.h"
#include "util-byte.h"

#define TDS_HDR_LEN 8

static int ParseTDSPktHdr(TDSPktHeader *hdr, uint8_t *in, uint32_t len);
static int TDSParseClientLogin(TDSState *s, uint8_t *input, uint32_t input_len, TDSPktHeader *hdr);
static int TDSParseSSPI(TDSState *s, uint8_t *input, uint32_t input_len, TDSPktHeader *hdr);
static int TDSLoginResp(TDSState *s, uint8_t *in, uint32_t len);
static int TDSServerResp(TDSState *s, uint8_t *in, uint32_t len);
static TDSTransaction *TDSTransactionAlloc(void);
static void TDStransactionFree(void *tx);
static void CleanCmd(TDSClientCommand *cmd);
static int ExtractSSPIField(char **field, uint16_t *len, uint16_t *max_len, uint8_t *begin, uint8_t *in);
static int ExtractClientField(char **dst, uint8_t *begin, uint8_t *in, uint32_t payload_len);

int TDSRequestParse(uint8_t *input, uint32_t ilen) {
	/* do nothing */ 
		 return 0;
}

int TDSParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    TDSState *s = alstate;
    SCEnter();

    if (!s)
        SCReturnInt(-1);

    if (!s->cur_tx) {
        TDSTransaction *tx = TDSTransactionAlloc();      
        if (!tx)
            return -1;
        s->cur_tx = tx;
        TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    }

    uint8_t *p = input;
    TDSPktHeader hdr;
    int ret;

    ret = ParseTDSPktHdr(&hdr, input, input_len);
    if (ret)
        SCReturnInt(-1);
    p += TDS_HDR_LEN;

    TDSClientCommand *cmd = &s->cur_tx->cmd;
    CleanCmd(cmd);

    cmd->tds_cmd = hdr.type;

    switch (hdr.type) {
        case TDS_QUERY: {
            cmd->sql_size = hdr.length - TDS_HDR_LEN;
            cmd->sql = SCCalloc(cmd->sql_size, 1);
            uint16_t idx = 0;
            uint8_t *sql = cmd->sql;
            /* because the SQL encoded in Unicode(every character
             * are 2 bytes, include ASCII character), we can not simply
             * use memcpy to dump the SQL statement */
            while (idx < cmd->sql_size) {
                /* for ascii, one of its bytes are '\0', and we skip it */
                if (p[idx] != '\0') {
                    *sql = p[idx];
                    ++sql;
                }
                ++idx;
            }
        }
        break;
        case TDS_LOGIN: 
            break;
        case TDS_RPC:
            break;
        case TDS_CANCEL:
            break;
        case TDS_BULK:
            break;
        case TDS7_LOGIN:
            TDSParseClientLogin(s, input, input_len, &hdr);
            break;
        case TDS_AUTH: /* SSPI message */
            TDSParseSSPI(s, input, input_len, &hdr);
            break;
        case TDS_PRELOGIN:
            break;
        default: break;
    }
    
    return 0;
}

int TDSParseServerRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data, AppLayerParserResult *output) {
    TDSState *s = alstate;
    SCEnter();

    if (!s)
        SCReturnInt(-1);

    if (!s->cur_tx) {
        TDSTransaction *tx = TDSTransactionAlloc();      
        if (!tx)
            return -1;
        s->cur_tx = tx;
        TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
    }

    return TDSServerResp(s, input, input_len);
}

void TDSStateFree(void *state) {
    SCEnter();
    TDSState *s = state;
    if (s) {
        TDSTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&s->tx_list))) {
            TAILQ_REMOVE(&s->tx_list, tx, next);
            TDStransactionFree(tx);
        }
        SCFree(s);
    }
}

void *TDSStateAlloc(void) {
    TDSState *s = SCMalloc(sizeof(TDSState));
    if (s == NULL)
        return NULL;
    memset(s, 0, sizeof(TDSState));

    TAILQ_INIT(&s->tx_list);
    return s;
}

static int TDSParseClientLogin(TDSState *s, uint8_t *input,
        uint32_t input_len, TDSPktHeader *hdr) {
    uint8_t *p = input;
    uint8_t *q = NULL;
    if (input_len < TDS_HDR_LEN)
        SCReturnInt(-1);

    /* TODO: need some test on @hdr */
    p += TDS_HDR_LEN;
    q = p; /* begin of packet, except header 8 bytes */

    uint32_t payload_len = hdr->length - TDS_HDR_LEN;

    uint32_t total_pkt_len, tds_ver, pkt_size, cli_version,
             cli_pid, conn_id, time_zone, collation;
    uint8_t opt_flag1, opt_flag2, sql_type_flag,
            reserved_flag;

    if (ByteExtractUint32(&total_pkt_len, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;
    if (ByteExtractUint32(&tds_ver, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;
    if (ByteExtractUint32(&pkt_size, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;
    if (ByteExtractUint32(&cli_version, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;
    if (ByteExtractUint32(&cli_pid, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;
    if (ByteExtractUint32(&conn_id, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    opt_flag1 = *p;
    ++p;
    opt_flag2 = *p;
    ++p;
    sql_type_flag = *p;
    ++p;
    reserved_flag = *p;
    ++p;

    if (ByteExtractUint32(&time_zone, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    if (ByteExtractUint32(&collation, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    if (p - input >= hdr->length)
        SCReturnInt(-1);

    /* to keep gcc silent */
    (void)total_pkt_len ;
    (void)pkt_size      ;
    (void)cli_version   ;
    (void)cli_pid       ;
    (void)conn_id       ;
    (void)time_zone     ;
    (void)collation;    ;
    (void)opt_flag1     ;
    (void)opt_flag2     ;
    (void)sql_type_flag ;
    (void)reserved_flag ;

    s->cur_tx->tds_version = tds_ver;
                         
    TDSClient *cli = &s->cur_tx->cli;

    if (ExtractClientField(&cli->client_name, q, p, payload_len ) == -1)
        goto error;
    p += 4;

    if (ExtractClientField(&cli->user_name, q, p, payload_len) == -1)
        goto error; 
    p += 4; 
    if (ExtractClientField(&cli->password, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (ExtractClientField(&cli->app_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (ExtractClientField(&cli->server_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    p += 4; /* skip unknown offset and length */

    if (ExtractClientField(&cli->library_name, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (ExtractClientField(&cli->locale, q, p, payload_len) == -1)
        goto error;
    p += 4;

    if (ExtractClientField(&cli->db_name, q, p, payload_len) == -1)
        goto error;

    if (p - q + TDS_HDR_LEN < hdr->length) {
        /* TODO: parse NTML secure service provider info */
    }

    s->cur_tx->try_login = 1;

    if (!cli->user_name && !cli->password)
        s->cur_tx->wait_auth = 1;

    return 0;
error:
    return -1;
}

/* we have no idea about the SSPI message */
struct ntlm_ssp_ {
    char *identifier;
    uint32_t mst_type;

    /* lan manager responce */
    uint16_t lmr_len; 
    uint16_t max_lmr_len;
    char *lan_mgr_resp; /* seems like 24 bytes */
    char *ntml_cli_challenge; /* part of (first 8 byte) @lan_mgr_resp */

    /* ntml response */
    uint16_t ntml_resp_len;
    uint16_t max_ntml_resp_len;
    char *ntml_resp;

    /* domain name */
    uint16_t domain_name_len;
    uint16_t max_domain_name_len;
    char *domain_name;

    /* user name */
    uint16_t user_name_len;
    uint16_t max_user_name_len;
    char *user_name;

    /* host name */
    uint16_t host_name_len;
    uint16_t max_host_name_len;
    char *host_name;

    /* session key */
    char session_key[8];

    uint32_t flags;
};

static void CleanSSPI(struct ntlm_ssp_ *sspi) {
    if (sspi == NULL)
        return;
    if (sspi->identifier != NULL)
        SCFree(sspi->identifier);
    if (sspi->lan_mgr_resp != NULL)
        SCFree(sspi->lan_mgr_resp);
    if (sspi->ntml_resp != NULL)
        SCFree(sspi->ntml_resp);
    if (sspi->domain_name != NULL)
        SCFree(sspi->domain_name);
    if (sspi->user_name != NULL)
        SCFree(sspi->user_name);
    if (sspi->host_name != NULL)
        SCFree(sspi->host_name);

    memset(sspi, 0, sizeof(*sspi));
}

static int TDSParseSSPI(TDSState *s, uint8_t *input,
        uint32_t input_len, TDSPktHeader *hdr) {
    struct ntlm_ssp_ sspi;
    uint8_t *p = input + TDS_HDR_LEN;
    uint8_t *q = input + TDS_HDR_LEN; /* begin */

    sspi.identifier = SCStrdup((const char *)p); /* identifier terminated with '\0' */
    p += (strlen((const char *)p) + 1);
    
    if (ByteExtractUint32(&sspi.mst_type, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        goto error;

    if (ExtractSSPIField(&sspi.lan_mgr_resp, &sspi.lmr_len, &sspi.max_lmr_len, q, p) == -1)
        goto error;
    sspi.ntml_cli_challenge = sspi.lan_mgr_resp;

    p += 8; /* offset 2 short and 1 int size */

    if (ExtractSSPIField(&sspi.ntml_resp, &sspi.ntml_resp_len, &sspi.max_ntml_resp_len, q, p) == -1)
        goto error;
    p += 8;

    if (ExtractSSPIField(&sspi.domain_name, &sspi.domain_name_len, &sspi.max_domain_name_len, q, p) == -1)
        goto error;
    p += 8;

    if (ExtractSSPIField(&sspi.user_name, &sspi.user_name_len, &sspi.max_user_name_len, q, p) == -1)
        goto error;
    p += 8;

    if (ExtractSSPIField(&sspi.host_name, &sspi.host_name_len, &sspi.max_host_name_len, q, p) == -1)
        goto error;
    p += 8;

    memcpy(sspi.session_key, p, sizeof(sspi.session_key));
    p += sizeof(sspi.session_key);

    if (ByteExtractUint32(&sspi.flags, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        goto error;

    if (s->cur_tx->wait_auth) {
       TDSClient *cli = &s->cur_tx->cli;
       if (cli->user_name)
           SCFree(cli->user_name);
       /* only copy user_name */
       cli->user_name = SCStrdup(sspi.user_name);
    }

    CleanSSPI(&sspi);
    return 0;

error:
    CleanSSPI(&sspi);
    return -1;
}

static int ExtractSSPIField(char **field, uint16_t *len, uint16_t *max_len, uint8_t *begin, uint8_t *in) {
    uint8_t *p = in;
    uint32_t off = 0;

    if (ByteExtractUint16(len, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;
    if (ByteExtractUint16(max_len, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    p += 2;

    if (ByteExtractUint32(&off, BYTE_LITTLE_ENDIAN, 4, p) <= 0)
        SCReturnInt(-1);
    p += 4;

    *field = SCCalloc(*len, 1);
    if (*field == NULL)
        SCReturnInt(-1);

    uint16_t idx = 0;
    char *q = *field;
    while (idx < *len) {
        if (begin[off + idx] != '\0') {
            *q = begin[off + idx];
            ++q;
        }
        ++idx;
    }
    return 0;
}

static int ParseTDSPktHdr(TDSPktHeader *hdr, uint8_t *in, uint32_t len) {
    uint8_t *p = in;
    uint16_t res = 0;

    hdr->type = *p;
    ++p;
    hdr->status = *p;
    ++p;

    hdr->length = (*p * 256) + *(p + 1);
    p += 2;

    if (ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        SCReturnInt(-1);
    hdr->channel = res;
    p += 2;
    hdr->pkt_number = *p;
    ++p;
    hdr->window = *p;
    return 0;
}

static int ExtractClientField(char **dst, uint8_t *begin, uint8_t *in, uint32_t payload_len) {
    uint16_t off, len;
    uint8_t *p = in;

    if (ByteExtractUint16(&off, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        return -1;

    p += 2;
    if (ByteExtractUint16(&len, BYTE_LITTLE_ENDIAN, 2, p) <= 0)
        return -1;

    if (len == 0 || off == 0) /* some field maybe optional */
        return 0;

    if (off + len >= payload_len)
        return -1;

    /* transfer unicode ascii string to ascii string, remove '\0' */
    int idx = 0;
    *dst = SCCalloc(len + 1, 1);
    char *q = *dst;
    while (len * 2 > idx) { /* FIXME: while ASCII was not unicode encoded, buggy */
        if (begin[off + idx] != '\0') {
            *q = begin[off + idx];
            ++q;
        }
        ++idx;
    }

    return 0;
}

static int TDSLoginResp(TDSState *s, uint8_t *in, uint32_t len) {
    /* TODO: parse more info from server response */
    s->cur_tx->login_ok = 1;
    return 0;
}

static void CleanCmd(TDSClientCommand *cmd) {
    if (cmd->sql_size) {
        SCFree(cmd->sql);
    }
    memset(cmd, 0, sizeof(*cmd));
}

static void CleanCli(TDSClient *cli) {
    if (!cli)
        return;
    if (cli->src_ip      ) SCFree(cli->src_ip      );
    if (cli->dst_ip      ) SCFree(cli->dst_ip      );
    if (cli->client_name ) SCFree(cli->client_name );
    if (cli->user_name   ) SCFree(cli->user_name   );
    if (cli->password    ) SCFree(cli->password    );
    if (cli->app_name    ) SCFree(cli->app_name    );
    if (cli->server_name ) SCFree(cli->server_name );
    if (cli->library_name) SCFree(cli->library_name);
    if (cli->locale      ) SCFree(cli->locale      );
    if (cli->db_name     ) SCFree(cli->db_name     );
}

static int TDSServerResp(TDSState *s, uint8_t *in, uint32_t len) {
    /* TODO */
    return 0;
}

static TDSTransaction *TDSTransactionAlloc(void) {
    TDSTransaction *tx = SCMalloc(sizeof(TDSTransaction));
    if (unlikely(tx == NULL))
        return NULL;
    memset(tx, 0, sizeof(*tx));
#if 0
    TAILQ_INIT(&tx->ppkt_list);
#endif
    return tx;
}

static void TDStransactionFree(void *transaction) {
    TDSTransaction *tx = transaction;
    if (tx == NULL)
        return;
    CleanCmd(&tx->cmd);
    CleanCli(&tx->cli);
    SCFree(tx);
}

const uint8_t *TDSCmdStr(size_t cmd) {
    static char *str[] = {
        "TDS_UNKNOWN(cmd=0)"    ,
        "TDS_QUERY"             ,
        "TDS_LOGIN"             ,
        "TDS_RPC"               ,
        "TDS_REPLY"             ,
        "TDS_UNKNOWN(cmd=5)"    ,
        "TDS_CANCEL"            ,
        "TDS_BULK"              ,
        "TDS_UNKNOWN(cmd=8)"    ,
        "TDS_UNKNOWN(cmd=9)"    ,
        "TDS_UNKNOWN(cmd=10)"   ,
        "TDS_UNKNOWN(cmd=11)"   ,
        "TDS_UNKNOWN(cmd=12)"   ,
        "TDS_UNKNOWN(cmd=13)"   ,
        "TDS_UNKNOWN(cmd=14)"   ,
        "TDS_NORMAL"            ,
        "TDS7_LOGIN"            ,
        "TDS_AUTH"              ,
        "TDS_PRELOGIN"          ,
    };

    static char *unknown[] = {"TDS_UNKNOWN(cmd=?)"};

    if (cmd < sizeof(str)/sizeof(char *))
        return (uint8_t *)str[cmd];
    return (uint8_t *)unknown;
}
