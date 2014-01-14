/**
 * \file
 * \author
 *
 * App-layer parser for Mysql protocol
 *
 */

#include "suricata-common.h"
#include "app-layer-mysql-common.h"

static uint16_t MysqlProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset) {
    if (ilen == 0 || ilen < sizeof(MysqlPktHeader)) {
        return ALPROTO_UNKNOWN;
    }

    if (MysqlRequestParse(input, ilen) == -1) {
        return ALPROTO_FAILED;
    }

    return ALPROTO_MYSQL;
}

void RegisterMysqlParsers(void) {
    char *proto_name = "mysql";

    if (AppLayerProtoDetectionEnabled(proto_name)) {
        if (RunmodeIsUnittests()) {
            AppLayerRegisterProbingParser(&alp_proto_ctx,
                    IPPROTO_TCP, "3306", proto_name,
                    ALPROTO_MYSQL, 0, sizeof(MysqlPktHeader),
                    STREAM_TOSERVER, MysqlProbingParser);
        } else {
            AppLayerParseProbingParserPorts(proto_name, ALPROTO_MYSQL, 0,
                    sizeof(MysqlPktHeader), MysqlProbingParser);

        }

        AppLayerRegisterParserAcceptableDataDirection(ALPROTO_MYSQL, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol", proto_name);
        return;
    }

    if (AppLayerParserEnabled(proto_name)) {
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOSERVER, MysqlParseClientRecord);
        AppLayerRegisterProto(proto_name, ALPROTO_MYSQL, STREAM_TOCLIENT, MysqlParseServerRecord);
        AppLayerRegisterStateFuncs(ALPROTO_MYSQL, MysqlStateAlloc, MysqlStateFree);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterUnittests(ALPROTO_MYSQL, MysqlParserRegisterTests);
#endif

    return;
}

#ifdef UNITTESTS
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "flow-util.h"
#include "util-unittest.h"

static MysqlState *ut_complete_state;
/** \test Server Send a handshake request in one chunk */
int MysqlParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x36, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x35,     0x2e, 0x32, 0x2d, 0x6d, 0x32, 0x00, 0x0b, 0x00,
        0x00, 0x00, 0x64, 0x76, 0x48, 0x40, 0x49, 0x2d,     0x43, 0x4a, 0x00, 0xff, 0xf7, 0x08, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x34, 0x64,
        0x7c, 0x63, 0x5a, 0x77, 0x6b, 0x34, 0x5e, 0x5d,     0x3a, 0x00 }; 
    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f,
            ALPROTO_MYSQL, STREAM_TOCLIENT | STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    ut_complete_state = f.alstate;
    if (ut_complete_state == NULL) {
        SCLogDebug("no mysql state: ");
        result = 0;
        goto end;
    }

    if (!ut_complete_state->cur_tx->hs) {
        result = 0;
        goto end;
    }
end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a login(auth) request in one chunk */
int MysqlParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0xb2, 0x00, 0x00, 0x01, 0x85, 0xa2, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14, 0x22, 0x50, 0x79, 0xa2, 0x12, 0xd4,
        0xe8, 0x82, 0xe5, 0xb3, 0xf4, 0x1a, 0x97, 0x75, 0x6b, 0xc8, 0xbe, 0xdb, 0x9f, 0x80, 0x6d, 0x79,
        0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77,
        0x6f, 0x72, 0x64, 0x00, 0x61, 0x03, 0x5f, 0x6f, 0x73, 0x09, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e,
        0x36, 0x2e, 0x30, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
        0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x04, 0x5f, 0x70, 0x69, 0x64, 0x05, 0x32,
        0x32, 0x33, 0x34, 0x34, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72,
        0x73, 0x69, 0x6f, 0x6e, 0x08, 0x35, 0x2e, 0x36, 0x2e, 0x36, 0x2d, 0x6d, 0x39, 0x09, 0x5f, 0x70,
        0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x03, 0x66,
        0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = ut_complete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (!s->cur_tx->try_auth) {
        result = 0;
        goto end;
    }
end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a query request in one chunk */
int MysqlParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, 0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = ut_complete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

end:
    MysqlStateFree(ut_complete_state);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a incomplete query request */
static MysqlState *ut_incomplete_state = NULL;
int MysqlParserTest04(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, //0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;

    MysqlTransaction *tx = NULL;
    if (ut_incomplete_state == NULL) {
        ut_incomplete_state = MysqlStateAlloc();
        tx = MysqlTransactionAlloc();
        tx->hs = 1;
        tx->try_auth = 1;
        tx->auth_ok = 1;

        ut_incomplete_state->cur_tx = tx;
    }

    MysqlState *s = ut_incomplete_state;
    PendingPkt *ppkt = s->cur_tx->cur_ppkt;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* for incomplete package, do not parse the pkt, so there is no cmd parsed */
    ppkt = s->cur_tx->cur_ppkt;
    if (ppkt->flags != PPKT_APPENDING) {
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send the rest of the query request */
int MysqlParserTest05(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = ut_incomplete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (s->cur_tx->cmd.cmd != MYSQL_COMMAND_QUERY) {
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a new command when there was a pending request */
int MysqlParserTest06(void) {
    int result = 1;
    Flow f;
    uint8_t buf[] = {
        0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
        0x6d, 0x69, 0x74, 0x20, 0x31
    };

    uint32_t buflen = sizeof(buf);
    TcpSession ssn;
    MysqlState *s = ut_incomplete_state;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alstate = s;

    StreamTcpInitConfig(TRUE);
    SCMutexLock(&f.m);
    int r = AppLayerParse(NULL, &f, ALPROTO_MYSQL,
            STREAM_TOSERVER|STREAM_EOF, buf, buflen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (s->cur_tx->cmd.cmd != MYSQL_COMMAND_QUERY) {
        result = 0;
        goto end;
    }

end:
    MysqlStateFree(s);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif

void MysqlParserRegisterTests(void) {
#ifdef UNITTESTS
    //UtRegisterTest("MysqlParserTest01", MysqlParserTest01, 1);
    //UtRegisterTest("MysqlParserTest02", MysqlParserTest02, 1);
    //UtRegisterTest("MysqlParserTest03", MysqlParserTest03, 1);

    /* porcess separated packet */
    //UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);
    //UtRegisterTest("MysqlParserTest05", MysqlParserTest05, 1);

    /* successive incomplete packet */
    UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);
    UtRegisterTest("MysqlParserTest04", MysqlParserTest04, 1);

    /* process complete packet again on old mysql state */
    //UtRegisterTest("MysqlParserTest06", MysqlParserTest06, 1);
#endif
}
