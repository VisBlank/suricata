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

typedef struct MySqlState_ {
    uint8_t *input;
    uint32_t input_len;
    uint8_t direction;

    /* TODO: add more */
} MySqlState;

#endif /* __APP_LAYER_MYSQL_H__ */
