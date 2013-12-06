/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Generic App-layer parsing functions.
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-unittest.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"
#include "flow-private.h"

#include "detect-engine-state.h"
#include "detect-engine-port.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-smb2.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"
#include "app-layer-dns-udp.h"
#include "app-layer-dns-tcp.h"

#include "conf.h"
#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#include "runmodes.h"

typedef struct AlpCtxThread_ {
    void *alproto_local_storage[FLOW_PROTO_MAX][ALPROTO_MAX];
} AlpCtxThread;


/**
 * \brief App layer protocol parser context.
 */
typedef struct AlppCtx_
{
    /* 0 - to_server, 1 - to_client. */
    int (*Parser[2])(Flow *f, void *protocol_state,
                     void *pstate,
                     uint8_t *input, uint32_t input_len,
                     void *local_storage);
    char logger;

    void *(*StateAlloc)(void);
    void (*StateFree)(void *);
    void (*StateTransactionFree)(void *, uint64_t);
    void *(*LocalStorageAlloc)(void);
    void (*LocalStorageFree)(void *);

    void (*Truncate)(void *, uint8_t);
    FileContainer *(*StateGetFiles)(void *, uint8_t);
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t);
    int (*StateHasEvents)(void *);

    int (*StateGetProgress)(void *alstate, uint8_t direction);
    uint64_t (*StateGetTxCnt)(void *alstate);
    void *(*StateGetTx)(void *alstate, uint64_t tx_id);
    int (*StateGetProgressCompletionStatus)(uint8_t direction);
    int (*StateGetEventInfo)(const char *event_name,
                             int *event_id, AppLayerEventType *event_type);

    /* Indicates the direction the parser is ready to see the data
     * the first time for a flow.  Values accepted -
     * STREAM_TOSERVER, STREAM_TOCLIENT */
    uint8_t first_data_dir;

#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
} AlppCtx;

typedef struct AlpCtx_ {
    AlppCtx ctxs[FLOW_PROTO_MAX][ALPROTO_MAX];
} AlpCtx;

typedef struct AlpParserState_ {
    uint8_t flags;

    /* Indicates the current transaction that is being inspected.
     * We have a var per direction. */
    uint64_t inspect_id[2];
    /* Indicates the current transaction being logged.  Unlike inspect_id,
     * we don't need a var per direction since we don't log a transaction
     * unless we have the entire transaction. */
    uint64_t log_id;
    /* State version, incremented for each update.  Can wrap around. */
    uint16_t version;

    /* Used to store decoder events. */
    AppLayerDecoderEvents *decoder_events;
} AlpParserState;

/* Static global version of the parser context.
 * Post 2.0 let's look at changing this to move it out to app-layer.c. */
static AlpCtx alp_ctx;

static void AlpTransactionsCleanup(uint16_t ipproto, AppProto alproto,
                                   void *alstate, void *pstate)
{
    SCEnter();

    AlpParserState *parser_state_store = pstate;
    uint64_t inspect = 0, log = 0;
    uint64_t min;
    AlppCtx *ctx = &alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto];

    if (ctx->StateTransactionFree == NULL)
        SCReturn;

    if (parser_state_store->inspect_id[0] < parser_state_store->inspect_id[1])
        inspect = parser_state_store->inspect_id[0];
    else
        inspect = parser_state_store->inspect_id[1];
    log = parser_state_store->log_id;

    if (ctx->logger == TRUE) {
        min = log < inspect ? log : inspect;
        if (min > 0)
            ctx->StateTransactionFree(alstate, min - 1);
    } else {
        if (inspect > 0)
            ctx->StateTransactionFree(alstate, inspect - 1);
    }
}













void *AlpAllocAlpParserState(void)
{
    AlpParserState *pstate = (AlpParserState *)SCMalloc(sizeof(*pstate));
    if (pstate == NULL)
        return NULL;
    memset(pstate, 0, sizeof(*pstate));

    return pstate;
}

void AlpDeAllocAlpParserState(void *pstate)
{
    if (((AlpParserState *)pstate)->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(((AlpParserState *)pstate)->decoder_events);
    SCFree(pstate);
}


int AlpSetup(void)
{
    SCEnter();

    memset(&alp_ctx, 0, sizeof(alp_ctx));

    SCReturnInt(0);
}

void *AlpGetCtxThread(void)
{
    SCEnter();

    AppProto i = 0;
    int j = 0;
    AlpCtxThread *tctx;

    tctx = SCMalloc(sizeof(*tctx));
    if (tctx == NULL)
        goto end;
    memset(tctx, 0, sizeof(*tctx));

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < ALPROTO_MAX; j++) {
            tctx->alproto_local_storage[i][j] =
                AlpGetProtocolParserLocalStorage(FlowGetReverseProtoMapping(i),
                                                 j);
        }
    }

 end:
    SCReturnPtr(tctx, "void *");
}

void AlpDestroyCtxThread(void *alpd_tctx)
{
    SCEnter();

    AppProto i = 0;
    int j = 0;
    AlpCtxThread *tctx = (AlpCtxThread *)alpd_tctx;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < ALPROTO_MAX; j++) {
            AlpDestroyProtocolParserLocalStorage(FlowGetReverseProtoMapping(i),
                                                 j,
                                                 tctx->alproto_local_storage[i][j]);
        }
    }

    SCReturn;
}

int AlpConfParserEnabled(const char *alproto_name)
{
    int enabled = 1;
    char param[100];
    ConfNode *node;
    int r;

#ifdef UNITTESTS
    if (run_mode == RUNMODE_UNITTEST)
        goto enabled;
#endif

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto_name, ".enabled");
    if (r < 0) {
        SCLogError(SC_ERR_FATAL, "snprintf failure.");
        exit(EXIT_FAILURE);
    } else if (r > (int)sizeof(param)) {
        SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
        exit(EXIT_FAILURE);
    }

    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogInfo("Entry for %s not found.", param);
        goto disabled;
    }

    if (strcasecmp(node->val, "yes") == 0) {
        goto enabled;
    } else if (strcasecmp(node->val, "no") == 0) {
        goto disabled;
    } else if (strcasecmp(node->val, "detection-only") == 0) {
        goto enabled;
    } else {
        SCLogError(SC_ERR_FATAL, "Invalid value found for %s.", param);
        exit(EXIT_FAILURE);
    }

 disabled:
    enabled = 0;
 enabled:
    return enabled;
}

/***** Parser related registration *****/

int AlpRegisterParser(uint16_t ipproto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    void *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        Parser[(direction & STREAM_TOSERVER) ? 0 : 1] = Parser;

    SCReturnInt(0);
}

void AlpRegisterParserAcceptableDataDirection(uint16_t ipproto, AppProto alproto,
                                              uint8_t direction)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].first_data_dir |=
        (direction & (STREAM_TOSERVER | STREAM_TOCLIENT));

    SCReturn;
}

void AlpRegisterStateFuncs(uint16_t ipproto, AppProto alproto,
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateAlloc =
        StateAlloc;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateFree =
        StateFree;

    SCReturn;
}

void AlpRegisterLocalStorageFunc(uint16_t ipproto, AppProto alproto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].LocalStorageAlloc =
        LocalStorageAlloc;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].LocalStorageFree =
        LocalStorageFree;

    SCReturn;
}

void AlpRegisterGetFilesFunc(uint16_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetFiles =
        StateGetFiles;

    SCReturn;
}

void AlpRegisterGetEventsFunc(uint16_t ipproto, AppProto alproto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetEvents =
        StateGetEvents;

    SCReturn;
}

void AlpRegisterHasEventsFunc(uint16_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents =
        StateHasEvents;

    SCReturn;
}

void AlpRegisterLogger(uint16_t ipproto, AppProto alproto)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger = TRUE;

    SCReturn;
}

void AlpRegisterTruncateFunc(uint16_t ipproto, AppProto alproto,
                             void (*Truncate)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate = Truncate;

    SCReturn;
}

void AlpRegisterGetStateProgressFunc(uint16_t ipproto, AppProto alproto,
    int (*StateGetProgress)(void *alstate, uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgress = StateGetProgress;

    SCReturn;
}

void AlpRegisterTxFreeFunc(uint16_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateTransactionFree = StateTransactionFree;

    SCReturn;
}

void AlpRegisterGetTxCnt(uint16_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTxCnt = StateGetTxCnt;

    SCReturn;
}

void AlpRegisterGetTx(uint16_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTx = StateGetTx;

    SCReturn;
}

void AlpRegisterGetStateProgressCompletionStatus(uint16_t ipproto,
                                                   uint16_t alproto,
    int (*StateGetProgressCompletionStatus)(uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgressCompletionStatus = StateGetProgressCompletionStatus;

    SCReturn;
}

void AlpRegisterGetEventInfo(uint16_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEventInfo = StateGetEventInfo;

    SCReturn;
}

/***** Get and transaction functions *****/

void *AlpGetProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        LocalStorageAlloc != NULL)
    {
        SCReturnPtr(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                    LocalStorageAlloc(), "void *");
    }

    SCReturnPtr(NULL, "void *");
}

void AlpDestroyProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto,
                                          void *local_data)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        LocalStorageFree != NULL)
    {
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            LocalStorageFree(local_data);
    }

    SCReturn;
}

uint64_t AlpGetTransactionLogId(void *pstate)
{
    SCEnter();

    SCReturnCT(((AlpParserState *)pstate)->log_id, "uint64_t");
}

void AlpSetTransactionLogId(void *pstate)
{
    SCEnter();

    ((AlpParserState *)pstate)->log_id++;

    SCReturn;
}

uint64_t AlpGetTransactionInspectId(void *pstate, uint8_t direction)
{
    SCEnter();

    SCReturnCT(((AlpParserState *)pstate)->
               inspect_id[direction & STREAM_TOSERVER ? 0 : 1], "uint64_t");
}

void AlpSetTransactionInspectId(void *pstate,
                                uint16_t ipproto, AppProto alproto, void *alstate,
                                uint8_t direction)
{
    SCEnter();

    uint8_t dir = (direction & STREAM_TOSERVER) ? 0 : 1;
    uint64_t total_txs = AlpGetTxCnt(ipproto, alproto, alstate);
    uint64_t idx = AlpGetTransactionInspectId(pstate, direction);
    int state_done_progress = AlpGetStateProgressCompletionStatus(ipproto, alproto, dir);
    void *tx;
    int state_progress;

    for (; idx < total_txs; idx++) {
        tx = AlpGetTx(ipproto, alproto, alstate, idx);
        if (tx == NULL)
            continue;
        state_progress = AlpGetStateProgress(ipproto, alproto, tx, dir);
        if (state_progress >= state_done_progress)
            continue;
        else
            break;
    }
    ((AlpParserState *)pstate)->inspect_id[dir] = idx;

    SCReturn;
}

AppLayerDecoderEvents *AlpGetDecoderEvents(void *pstate)
{
    SCEnter();

    SCReturnPtr(((AlpParserState *)pstate)->decoder_events,
                "AppLayerDecoderEvents *");
}

void AlpSetDecoderEvents(void *pstate, AppLayerDecoderEvents *devents)
{
    (((AlpParserState *)pstate)->decoder_events) = devents;
}

AppLayerDecoderEvents *AlpGetEventsByTx(uint16_t ipproto, AppProto alproto,
                                        void *alstate, uint64_t tx_id)
{
    SCEnter();

    AppLayerDecoderEvents *ptr = NULL;

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEvents != NULL)
    {
        ptr = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetEvents(alstate, tx_id);
    }

    SCReturnPtr(ptr, "AppLayerDecoderEvents *");
}

uint16_t AlpGetStateVersion(void *pstate)
{
    SCEnter();
    if (pstate == NULL)
        SCReturnUInt(0);
    SCReturnUInt(((AlpParserState *)pstate)->version);
}

FileContainer *AlpGetFiles(uint16_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction)
{
    SCEnter();

    FileContainer *ptr = NULL;

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetFiles != NULL)
    {
        ptr = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetFiles(alstate, direction);
    }

    SCReturnPtr(ptr, "FileContainer *");
}

int AlpGetStateProgress(uint16_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction)
{
    SCEnter();
    SCReturnInt(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetProgress(alstate, direction));
}

uint64_t AlpGetTxCnt(uint16_t ipproto, AppProto alproto, void *alstate)
{
    SCEnter();
    SCReturnCT(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               StateGetTxCnt(alstate), "uint64_t");
}

void *AlpGetTx(uint16_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id)
{
    SCEnter();
    SCReturnPtr(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetTx(alstate, tx_id), "void *");
}

int AlpGetStateProgressCompletionStatus(uint16_t ipproto, AppProto alproto,
                                        uint8_t direction)
{
    SCEnter();
    SCReturnInt(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetProgressCompletionStatus(direction));

}

int AlpGetEventInfo(uint16_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);

    if (alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo == NULL)
        SCReturnInt(-1);

    SCReturnInt(alp_ctx.ctxs[ipproto_map][alproto].
                StateGetEventInfo(event_name, event_id, event_type));
}

uint8_t AlpGetFirstDataDir(uint16_t ipproto, uint16_t alproto)
{
    SCEnter();
    SCReturnCT(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               first_data_dir, "void *");
}

uint64_t AlpGetTransactionActive(uint16_t ipproto, AppProto alproto, void *pstate, uint8_t direction)
{
    AlpParserState *pstate_1 = (AlpParserState *)pstate;

    uint64_t log_id = pstate_1->log_id;
    uint64_t inspect_id = pstate_1->inspect_id[direction & STREAM_TOSERVER ? 0 : 1];
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger == TRUE) {
        return (log_id < inspect_id) ? log_id : inspect_id;
    } else {
        return inspect_id;
    }
}

/***** General *****/

int AlpParseL7Data(void *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    AlpParserState *pstate = NULL;
    AlppCtx *p = &alp_ctx.ctxs[FlowGetProtoMapping(f->proto)][alproto];
    TcpSession *ssn = NULL;
    void *alstate = NULL;
    AlpCtxThread *alp_tctx = (AlpCtxThread *)tctx;

    /* Used only if it's TCP */
    ssn = f->protoctx;

    /* Do this check before calling AppLayerParse */
    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), "
                   "this is not yet supported.");

        if (f->alstate != NULL)
            AlpStreamTruncated(f->proto, alproto, f->alstate, flags);
        goto error;
    }

    /* Get the parser state (if any) */
    pstate = f->alparser;
    if (pstate == NULL) {
        f->alparser = pstate = AlpAllocAlpParserState();
        if (pstate == NULL)
            goto error;
    }
    pstate->version++;
    SCLogDebug("app layer parser state version incremented to %"PRIu16,
               pstate->version);

    if (flags & STREAM_EOF)
        AlpParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);

    alstate = f->alstate;
    if (alstate == NULL) {
        f->alstate = alstate = p->StateAlloc();
        if (alstate == NULL)
            goto error;
        SCLogDebug("alloced new app layer state %p (name %s)",
                   alstate, AppLayerGetProtoString(f->alproto));
    } else {
        SCLogDebug("using existing app layer state %p (name %s))",
                   alstate, AppLayerGetProtoString(f->alproto));
    }

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0) {
        /* invoke the parser */
        if (p->Parser[(flags & STREAM_TOSERVER) ? 0 : 1](f, alstate, pstate,
                input, input_len,
                alp_tctx->alproto_local_storage[FlowGetProtoMapping(f->proto)][alproto]) < 0)
            {
                goto error;
            }
    }

    /* set the packets to no inspection and reassembly if required */
    if (pstate->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        AlpSetEOF(pstate);
        FlowSetNoPayloadInspectionFlag(f);
        FlowSetSessionNoApplayerInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (pstate->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            if (ssn != NULL) {
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                                                    flags & STREAM_TOCLIENT ? 1 : 0);
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                                                    flags & STREAM_TOSERVER ? 1 : 0);
            }
        }
    }

    /* next, see if we can get rid of transactions now */
    AlpTransactionsCleanup(f->proto, alproto, alstate, pstate);

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH)
        AlpStreamTruncated(f->proto, alproto, alstate, flags);

    SCReturnInt(0);
 error:
    if (ssn != NULL) {
        /* Set the no app layer inspection flag for both
         * the stream in this Flow */
        FlowSetSessionNoApplayerInspectionFlag(f);
        AlpSetEOF(pstate);
    }

    SCReturnInt(-1);
}

void AlpSetEOF(void *pstate)
{
    SCEnter();

    if (pstate == NULL)
        SCReturn;

    AlpParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);
    /* increase version so we will inspect it one more time
     * with the EOF flags now set */
    ((AlpParserState *)pstate)->version++;

    SCReturn;
}

int AlpHasDecoderEvents(uint16_t ipproto, AppProto alproto,
                        void *alstate, void *pstate,
                        uint8_t flags)
{
    SCEnter();

    if (alstate == NULL || pstate == NULL)
        return 0;

    AppLayerDecoderEvents *decoder_events;
    uint64_t tx_id;
    uint64_t max_id;

    if (AlpProtocolIsTxEventAware(ipproto, alproto)) {
        /* fast path if supported by alproto */
        if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents != NULL) {
            if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateHasEvents(alstate) == 1)
            {
                return 1;
            }
        } else {
            /* check each tx */
            tx_id = AlpGetTransactionInspectId(pstate, flags);
            max_id = AlpGetTxCnt(ipproto, alproto, alstate);
            for ( ; tx_id < max_id; tx_id++) {
                decoder_events = AlpGetEventsByTx(ipproto, alproto, alstate, tx_id);
                if (decoder_events && decoder_events->cnt)
                    return 1;
            }
        }
    }

    decoder_events = AlpGetDecoderEvents(pstate);
    if (decoder_events && decoder_events->cnt)
        return 1;

    return 0;
}

int AlpProtocolIsTxEventAware(uint16_t ipproto, AppProto alproto)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents != NULL)
        SCReturnInt(1);
    else
        SCReturnInt(0);
}

int AlpProtocolSupportsTxs(uint16_t ipproto, AppProto alproto)
{
    SCEnter();
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateTransactionFree != NULL)
        SCReturnInt(1);
    else
        SCReturnInt(0);
}

void AlpTriggerRawStreamReassembly(Flow *f)
{
    SCEnter();

    if (f != NULL && f->protoctx != NULL)
        StreamTcpReassembleTriggerRawReassembly(f->protoctx);

    SCReturn;
}

/***** Cleanup *****/

void AlpCleanupParserState(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate)
{
    AlppCtx *ctx = &alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto];

    if (ctx->StateFree != NULL && alstate != NULL)
        ctx->StateFree(alstate);

    /* free the app layer parser api state */
    if (pstate != NULL)
        AlpDeAllocAlpParserState(pstate);

    return;
}


void AlpRegisterProtocolParsers(void)
{
    RegisterHTPParsers();
    RegisterSSLParsers();
    RegisterSMBParsers();
    /** \todo bug 719 */
    //RegisterSMB2Parsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    /* we are disabling the ssh parser temporarily, since we are moving away
     * from some of the archaic features we use in the app layer.  We will
     * reintroduce this parser.  Also do note that keywords that rely on
     * the ssh parser would now be disabled */
#if 0
    RegisterSSHParsers();
#endif
    RegisterSMTPParsers();
    RegisterDNSUDPParsers();
    RegisterDNSTCPParsers();

    return;
}


void AlpParserStateSetFlag(void *pstate, uint8_t flag)
{
    ((AlpParserState *)pstate)->flags |= flag;
}

int AlpParserStateIssetFlag(void *pstate, uint8_t flag)
{
    return (((AlpParserState *)pstate)->flags & flag);
}


void AlpStreamTruncated(uint16_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate != NULL)
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate(alstate, direction);

    SCReturn;
}



#ifdef DEBUG
void AlpPrintDetailsParserState(void *pstate)
{
    SCEnter();

    if (pstate == NULL)
        SCReturn;

    AlpParserState *p = (AlpParserState *)pstate;
    SCLogDebug("Alp parser state information for parser state p(%p). "
               "p->inspect_id[0](%"PRIu64"), "
               "p->inspect_id[1](%"PRIu64"), "
               "p->log_id(%"PRIu64"), "
               "p->version(%"PRIu16"), "
               "p->decoder_events(%p).",
               pstate, p->inspect_id[0], p->inspect_id[1], p->log_id,
               p->version, p->decoder_events);

    SCReturn;
}
#endif





/***** Unittests *****/

#ifdef UNITTESTS

static AlpCtx alp_ctx_backup_unittest;

void AlpRegisterUnittests(uint16_t alproto, void (*RegisterUnittests)(void));
void AlpBackupParserTable(void)
{
    alp_ctx_backup_unittest = alp_ctx;
}
void AlpRestoreParserTable(void)
{
    alp_ctx = alp_ctx_backup_unittest;
}

#endif

