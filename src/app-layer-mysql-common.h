#ifndef __APP_LAYER_MYSQL_COMMON_H__
#define __APP_LAYER_MYSQL_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "queue.h"

/* transaction status */
#define MYSQL_STATE_INITIAL          0x00
#define MYSQL_STATE_SERVER_HANDSHAKE 0x01
#define MYSQL_STATE_CLIENT_AUTH      0x02
#define MYSQL_STATE_SERVER_AUTH_RESP 0x04
#define MYSQL_STATE_CLIENT_COMMAND   0x08
#define MYSQL_STATE_SERVER_RESPONSE  0x10
#define MYSQL_STATE_CLIENT_QUIT      0x20
#define MYSQL_STATE_INVALID          0x40

typedef enum {
	MYSQL_COMMAND_SLEEP               = 0x00, MYSQL_COMMAND_QUIT             = 0x01,
	MYSQL_COMMAND_INIT_DB             = 0x02, MYSQL_COMMAND_QUERY            = 0x03,
	MYSQL_COMMAND_FIELD_LIST          = 0x04, MYSQL_COMMAND_CREATE_DB        = 0x05,
	MYSQL_COMMAND_DROP_DB             = 0x06, MYSQL_COMMAND_REFRESH          = 0x07,
	MYSQL_COMMAND_SHUTDOWN            = 0x08, MYSQL_COMMAND_STATISTICS       = 0x09,
	MYSQL_COMMAND_PROCESS_INFO        = 0x0a, MYSQL_COMMAND_CONNECT          = 0x0b,
	MYSQL_COMMAND_PROCESS_KILL        = 0x0c, MYSQL_COMMAND_DEBUG            = 0x0d,
	MYSQL_COMMAND_PING                = 0x0e, MYSQL_COMMAND_TIME             = 0x0f,
	MYSQL_COMMAND_DELAYED_INSERT      = 0x10, MYSQL_COMMAND_CHANGE_USER      = 0x11,
	MYSQL_COMMAND_BINLOG_DUMP         = 0x12, MYSQL_COMMAND_TABLE_DUMP       = 0x13,
	MYSQL_COMMAND_CONNECT_OUT         = 0x14, MYSQL_COMMAND_REGISTER_SLAVE   = 0x15,
	MYSQL_COMMAND_STMT_PREPARE        = 0x16, MYSQL_COMMAND_STMT_EXECUTE     = 0x17,
	MYSQL_COMMAND_STMT_SEND_LONG_DATA = 0x18, MYSQL_COMMAND_STMT_CLOSE       = 0x19,
	MYSQL_COMMAND_STMT_RESET          = 0x1a, MYSQL_COMMAND_SET_OPTION       = 0x1b,
	MYSQL_COMMAND_STMT_FETCH          = 0x1c, MYSQL_COMMAND_DAEMON           = 0x1d,
	MYSQL_COMMAND_BINLOG_DUMP_GTID    = 0x1e, MYSQL_COMMAND_RESET_CONNECTION = 0x1f,

    /* commands not from Mysql, just append them */
    MYSQL_COMMAND_LOGIN               = 0x20,
    MYSQL_COMMAND_PENDING             = 0x21,
    MYSQL_COMMAND_DO_NOT_EXIST /* do not declare command after me */
} MysqlCommand;

/* comes from include/mysql_com.h */
enum client_flags {
    CLIENT_LONG_PASSWORD       = 1      , /* new more secure passwords */
    CLIENT_FOUND_ROWS          = 2      , /* Found instead of affected rows */
    CLIENT_LONG_FLAG           = 4      , /* Get all column flags */
    CLIENT_CONNECT_WITH_DB     = 8      , /* One can specify db on connect */
    CLIENT_NO_SCHEMA           = 16     , /* Don't allow database.table.column */
    CLIENT_COMPRESS            = 32     , /* Can use compression protocol */
    CLIENT_ODBC                = 64     , /* Odbc client */
    CLIENT_LOCAL_FILES         = 128    , /* Can use LOAD DATA LOCAL */
    CLIENT_IGNORE_SPACE        = 256    , /* Ignore spaces before '(' */
    CLIENT_PROTOCOL_41         = 512    , /* New 4.1 protocol */
    CLIENT_INTERACTIVE         = 1024   , /* This is an interactive client */
    CLIENT_SSL                 = 2048   , /* Switch to SSL after handshake */
    CLIENT_IGNORE_SIGPIPE      = 4096   , /* IGNORE sigpipes */
    CLIENT_TRANSACTIONS        = 8192   , /* Client knows about transactions */
    CLIENT_RESERVED            = 16384  , /* Old flag for 4.1 protocol */
    CLIENT_SECURE_CONNECTION   = 32768  , /* New 4.1 authentication */
    CLIENT_MULTI_STATEMENTS    = 65536  , /* Enable/disable multi-stmt support */
    CLIENT_MULTI_RESULTS       = 131072 , /* Enable/disable multi-results */
};

/**
 * \brief mysql package header (4 bytes)
 */
typedef struct MysqlPktHeader_ {
    uint32_t payload_len:24;
    int sequence_id:8;
} MysqlPktHeader;

typedef struct MysqlClient_ {
    char *username;
    int client_attr; /* attributes the client support */
    int max_pkt_len;

    char *db_name;
    char charset;
} MysqlClient;

enum ppkt_flags {
    PPKT_DROP,
    PPKT_APPENDING,
    PPKT_COMPLETE,
};

typedef struct PendingPkt_ {
    uint32_t pkt_len;
    uint32_t cur_len;
    uint8_t *pkt;
    uint8_t flags;
    TAILQ_ENTRY(PendingPkt_) next;
} PendingPkt;

/**
 * \brief MySQL transaction, request/reply with same TX id
 */
typedef struct MysqlState_ MysqlState;
typedef struct MysqlTransaction_ {
    MysqlState *s;
    uint16_t tx_id;

    uint8_t replied; /* bool indicating request is replied to. */
    uint8_t reply_lost;
    uint8_t reply_error; /* server say error or no on command */
    uint8_t logged, detected;

    uint8_t *sql;
    uint32_t sql_len;
    MysqlCommand cmd;

    int action; /* detect module related */
    TAILQ_ENTRY(MysqlTransaction_) next;
} MysqlTransaction;

#define STATE_USER(s) (s)->cur_tx->cli.username
#define STATE_USE_DB(s) (s)->cur_tx->cli.db_name
#define STATE_USE_CMD(s) (s)->cur_tx->cmd.cmd
#define STATE_SQL_CMD(s) (s)->cur_tx->cmd.sql

typedef struct MysqlState_ {
    TAILQ_HEAD(, MysqlTransaction_) tx_list;
    MysqlTransaction *cur_tx;
    MysqlPktHeader hdr;

    MysqlClient cli; /* transaction must map to a client */
    uint8_t *protocol_name;

    uint8_t pending;
    uint8_t *payload;
    uint32_t recved_len, payload_len;

    /* flags */
    uint8_t hs;     /* server handshake */
    uint8_t try_auth; /* client auth */
    uint8_t auth_ok;  /* auth passed */
    uint16_t tx_num;
} MysqlState;

int MysqlParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data);

int MysqlParseServerRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len, void *local_data);

void *MysqlStateAlloc(void);
void MysqlStateFree(void *state);
int MysqlRequestParse(uint8_t *input, uint32_t input_len);
const char *CmdStr(MysqlCommand cmd);

uint64_t MysqlGetTxCnt(void *alstate);
void *MysqlGetTx(void *alstate, uint64_t tx_id);
void MysqlStateTxFree(void *state, uint64_t tx_id);
int MysqlGetAlstateProgressCompletionStatus(uint8_t dir);
int MysqlGetAlstateProgress(void *tx, uint8_t direction);
#endif
