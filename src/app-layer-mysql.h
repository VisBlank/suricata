/**
 * \file
 * \author
 */

#ifndef __APP_LAYER_MYSQL_H__
#define __APP_LAYER_MYSQL_H__


typedef enum {
	MYSQL_COMMAND_SLEEP               = 0x00,
	MYSQL_COMMAND_QUIT                = 0x01,
	MYSQL_COMMAND_INIT_DB             = 0x02,
	MYSQL_COMMAND_QUERY               = 0x03,
	MYSQL_COMMAND_FIELD_LIST          = 0x04,
	MYSQL_COMMAND_CREATE_DB           = 0x05,
	MYSQL_COMMAND_DROP_DB             = 0x06,
	MYSQL_COMMAND_REFRESH             = 0x07,
	MYSQL_COMMAND_SHUTDOWN            = 0x08,
	MYSQL_COMMAND_STATISTICS          = 0x09,
	MYSQL_COMMAND_PROCESS_INFO        = 0x0a,
	MYSQL_COMMAND_CONNECT             = 0x0b,
	MYSQL_COMMAND_PROCESS_KILL        = 0x0c,
	MYSQL_COMMAND_DEBUG               = 0x0d,
	MYSQL_COMMAND_PING                = 0x0e,
	MYSQL_COMMAND_TIME                = 0x0f,
	MYSQL_COMMAND_DELAYED_INSERT      = 0x10,
	MYSQL_COMMAND_CHANGE_USER         = 0x11,
	MYSQL_COMMAND_BINLOG_DUMP         = 0x12,
	MYSQL_COMMAND_TABLE_DUMP          = 0x13,
	MYSQL_COMMAND_CONNECT_OUT         = 0x14,
	MYSQL_COMMAND_REGISTER_SLAVE      = 0x15,
	MYSQL_COMMAND_STMT_PREPARE        = 0x16,
	MYSQL_COMMAND_STMT_EXECUTE        = 0x17,
	MYSQL_COMMAND_STMT_SEND_LONG_DATA = 0x18,
	MYSQL_COMMAND_STMT_CLOSE          = 0x19,
	MYSQL_COMMAND_STMT_RESET          = 0x1a,
	MYSQL_COMMAND_SET_OPTION          = 0x1b,
	MYSQL_COMMAND_STMT_FETCH          = 0x1c,
	MYSQL_COMMAND_DAEMON              = 0x1d,
	MYSQL_COMMAND_BINLOG_DUMP_GTID    = 0x1e,
	MYSQL_COMMAND_RESET_CONNECTION    = 0x1f,
} MySqlRequestCommand;

#define MYSQL_FLAGS_CLIENT_VERSION_PARSED 0x01
//#define MYSQL_FLAGS_SERVER_VERSION_PARSED 0x02
//

#define MYSQL_DIRECTION_TO_SERVER 0x00
#define MYSQL_DIRECTION_TO_CLIENT 0x01

typedef struct MySqlServerHandshake_{
    int payload_len:3;
    int sequence_id:1;
    char protocol;
    char charset;
    char reserved_0;
    char reserved_1;
    char reserved_10[10]; /* reserved 10 bytes */
    char crypt_part2[12];
    int conn_id;
    char crypt_part1[8];
    short server_attr_l; /* low 2 bytes */
    short server_attr_h; /* high 2 bytes */
    short server_state;
    char *client_version; /* dynamic length */
} MySqlServerHandshake;

typedef struct MySqlClientAuth_ {
    int payload_len:3;
    int sequence_id:1;
    int client_available_attr;
    int max_pkt_len;
    char charset;
    char reserved[23];
    char *username;
    char password_len;
    char *password;
    char *initial_db_name;
} MySqlClientAuth_;

typedef struct MySqlResponse_ {
    int payload_len:3;
    int sequence_id:1;
    char state;
    char affected_rows[9]; /* lenenc_int, maybe 1,3,4,9 bytes */
    char last_insert_id[9]; /* lenenc_int, maybe 1,3,4,9 bytes */
    short warnings;
    char *msg;
} MySqlResponse;

typedef struct MySqlState_ {
    uint8_t flags;
    uint8_t *input;
    uint32_t input_len;
    uint8_t direction;

    /* TODO: add more */
} MySqlState;

void RegisterMySqlParsers(void);

#endif /* __APP_LAYER_MYSQL_H__ */
