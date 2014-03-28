/*
 * Oracle 11g TNS implementation
 * author: coanor <coanor@gmail.com>
 * date: Fri Mar 28 14:34:15 CST 2014
 */

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-byte.h"
#include "queue.h"

typedef struct TNS11gTransaction_ {
	uint8_t *username, *dbname;
	uint16_t sql_size;
	uint8_t *sql;
	uint8_t *meta_info;
	TAILQ_ENTRY(TNS11gTransaction_) next;
} TNS11gTransaction;

typedef struct TNS11gState_ {
	TAILQ_HEAD(, TNS11gTransaction_) tx_list;
	TNS11gTransaction *cur_tx;
} TNS11gState;

void *TNS11gStateAlloc(void) {
	TNS11gState *s = SCCalloc(sizeof(*s), 1);
	if (unlikely(s == NULL))
		return NULL;
	TAILQ_INIT(&s->tx_list);
	return s;
}

static void TNS11gTransactionFree(TNS11gTransaction *tx) {
	if (tx) {
		SCFree(tx->sql);
		SCFree(tx->username);
		SCFree(tx->dbname);
		SCFree(tx);
	}
}

void TNS11gStateFree(void *state) {
	SCEnter();
	TNS11gState *s = state;
	if (s) {
		TNS11gState *s = (TNS11gState *)state;
		TNS11gTransaction *tx = NULL;
		while ((tx = TAILQ_FIRST(&s->tx_list))) {
			TAILQ_REMOVE(&s->tx_list, tx, next);
			TNS11gTransactionFree(tx);
		}

		SCFree(s);
	}
}

/* search @str from @mem to @mem + @mem_size */
static memstr(char *mem, const char *str, uint32_t mem_size, uint32_t str_len) {
	char *p = mem;
	while (p < mem + mem_size) {
		if (*p == str[0]) {
			if (!strncpy(p, str, str_len)) {
				return p;
			}
		}
	}
	return NULL;
}

static int DumpBinary(TNS11gState *s, uint8_t *in, uint32_t len) {
	uint8_t *dump = SCCalloc(len * 2 + 1, 1);
	uint8_t *p = in;
	uint8_t *q = dump;
	char hex[4];

	while (p < in + len) {
		if (isalnum(*p)) { /* only dump alpha and number as original */
			*q = *p;
			++q;
		} else {
			sprintf(hex, "%x ", *p);
			memcpy(q, hex, 2);
			q += 2;
		}
	}

	if (s->cur_tx->sql) { /* release previous sql dump */
		SCFree(s->cur_tx->sql);
	}

	s->cur_tx->sql = dump;
	s->cur_tx->sql_size = len;

	SCReturnInt(0);
}

static int TNS11gParseLogin(TNS11gState *s, uint8_t *in, uint32_t len) {
	char *meta_info = memstr(in, "(DESCRIPTION", len, sizeof("(DESCRIPTION") - 1);

	char *p = memstr(in, "USER=", len, sizeof("USER=") - 1);
	if (p == NULL)
		SCReturnInt(-1);

	char *q = p + sizeof("USER=") - 1;
	for (;;) {
		if (*q == ')')
			break;
		++q;
	}

	assert(q > p);

	uint8_t *data = SCCalloc(q - p + 1, 1);
	if (unlikely(data == NULL))
		SCReturnInt(-1);

	memcpy(data, p, q - p);
	if (s->cur_tx->username)
		SCFree(s->cur_tx->username);
	s->cur_tx->username = data;

	p = memstr(in, "SERVICE_NAME=", len, sizeof("SERVICE_NAME=") - 1);
	if (p == NULL)
		SCReturnInt(-1);
	q = p + sizeof("SERVICE_NAME=") - 1;
	for (;;) {
		if (*q == ')')
			break;
		++q;
	}

	assert(q > p);
	data = SCCalloc(q - p + 1, 1);
	if (unlikely(data == NULL))
		SCReturnInt(-1);
	memcpy(data, p, q - p);

	if (s->cur_tx->dbname)
		SCFree(s->cur_tx->dbname);
	s->cur_tx->dbname = data;

	s->cur_tx->meta_info = SCStrdup(meta_info);
	SCReturnInt(0);
}

int TNS11gParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data) {

    int offset = 0;
    TNS11gState *s = alstate;
	TNS11gTransaction *tx = NULL;
	static int tns11g_hdr_len = 8;

	uint16_t res = 0;
	int len = ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, in + offset);
	if (res < tns11g_hdr_len) {
		return 0; /* not a tns packet */
	}

	switch (in[5]) {
		case 0x1: /* login */
			tx = SCCalloc(sizeof(*tx), 1);
			TAILQ_INSERT_HEAD(&s->tx_list, tx, next);
			s->cur_tx = tx;
			TNS11gParseLogin(s, in, len);
			break;
		case 0x6: /* data */
			DumpBinary(s, in, len);
	}
}
