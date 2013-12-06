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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-engine-port.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-private.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "conf.h"
#include "util-memcmp.h"
#include "util-spm.h"
#include "util-cuda.h"
#include "util-debug.h"

#include "runmodes.h"


typedef struct AlpdProbingParserElement_ {
    uint16_t alproto;
    /* \todo don't really need it.  See if you can get rid of it */
    uint16_t port;
    /* \todo calculate at runtime and get rid of this var */
    uint32_t alproto_mask;
    /* \todo check if we can reduce the bottom 2 vars to uint16_t */
    /* the min length of data that has to be supplied to invoke the parser */
    uint32_t min_depth;
    /* the max length of data after which this parser won't be invoked */
    uint32_t max_depth;
    /* the probing parser function */
    ProbingParserFPtr ProbingParser;

    struct AlpdProbingParserElement_ *next;
} AlpdProbingParserElement;

typedef struct AlpdProbingParserPort_ {
    /* the port no for which probing parser(s) are invoked */
    uint16_t port;

    uint32_t toserver_alproto_mask;
    uint32_t toclient_alproto_mask;
    /* the max depth for all the probing parsers registered for this port */
    uint16_t toserver_max_depth;
    uint16_t toclient_max_depth;

    AlpdProbingParserElement *toserver;
    AlpdProbingParserElement *toclient;

    struct AlpdProbingParserPort_ *next;
} AlpdProbingParserPort;

typedef struct AlpdProbingParser_ {
    uint16_t ip_proto;
    AlpdProbingParserPort *port;

    struct AlpdProbingParser_ *next;
} AlpdProbingParser;




typedef struct AlpdPMSignature_ {
    AppProto alproto;
    /* todo Change this into a non-pointer */
    DetectContentData *cd;
    struct AlpdPMSignature_ *next;
} AlpdPMSignature;

typedef struct AlpdPMCtx_ {
    uint16_t max_len;
    uint16_t min_len;
    MpmCtx mpm_ctx;

    /** Mapping between pattern id and signature.  As each signature has a
     *  unique pattern with a unique id, we can lookup the signature by
     *  the pattern id. */
    AlpdPMSignature **map;
    AlpdPMSignature *head;

    /* \todo we don't need this except at setup time.  Get rid of it. */
    PatIntId max_pat_id;
} AlpdPMCtx;

typedef struct AlpdCtxIpproto_ {
    /* 0 - toserver, 1 - toclient */
    AlpdPMCtx ctx_pm[2];
} AlpdCtxIpproto;

/**
 * \brief The app layer protocol detection context.
 */
typedef struct AlpdCtx_ {
    /* Context per ip_proto.
     * \todo Modify ctx_ipp to hold for only tcp and udp. The rest can be
     *       implemented if needed.  Waste of space otherwise. */
    AlpdCtxIpproto ctx_ipp[FLOW_PROTO_DEFAULT];

    AlpdProbingParser *ctx_pp;

    /* Indicates the protocols that have registered themselves
     * for protocol detection.  This table is independent of the
     * ipproto. */
    char *alproto_names[ALPROTO_MAX];
} AlpdCtx;

/**
 * \brief The app layer protocol detection thread context.
 */
typedef struct AlpdCtxThread_ {
    PatternMatcherQueue pmq;
    /* The value 2 is for direction(0 - toserver, 1 - toclient). */
    MpmThreadCtx mpm_tctx[FLOW_PROTO_DEFAULT][2];
} AlpdCtxThread;

AlpdCtx alpd_ctx;

/***** API *****/

static uint16_t AlpdPMMatchSignature(AlpdPMSignature *s,
                                     uint8_t *buf, uint16_t buflen,
                                     uint16_t ipproto)
{
    SCEnter();
    uint16_t proto = ALPROTO_UNKNOWN;
    uint8_t *found = NULL;

    if (s->cd->offset > buflen) {
        SCLogDebug("s->co->offset (%"PRIu16") > buflen (%"PRIu16")",
                   s->cd->offset, buflen);
        goto end;
    }

    if (s->cd->depth > buflen) {
        SCLogDebug("s->co->depth (%"PRIu16") > buflen (%"PRIu16")",
                   s->cd->depth, buflen);
        goto end;
    }

    uint8_t *sbuf = buf + s->cd->offset;
    uint16_t sbuflen = s->cd->depth - s->cd->offset;
    SCLogDebug("s->co->offset (%"PRIu16") s->cd->depth (%"PRIu16")",
               s->cd->offset, s->cd->depth);

    if (s->cd->flags & DETECT_CONTENT_NOCASE)
        found = SpmNocaseSearch(sbuf, sbuflen, s->cd->content, s->cd->content_len);
    else
        found = SpmSearch(sbuf, sbuflen, s->cd->content, s->cd->content_len);
    if (found != NULL)
        proto = s->alproto;

 end:
    SCReturnInt(proto);
}

static uint16_t AlpdPMGetProto(AlpdCtxThread *tctx,
                               Flow *f,
                               uint8_t *buf, uint16_t buflen,
                               uint8_t flags,
                               uint8_t ipproto,
                               AppProto *pm_results)
{
    SCEnter();

    pm_results[0] = ALPROTO_UNKNOWN;

    AlpdPMCtx *pm_ctx;
    MpmThreadCtx *mpm_tctx;
    uint16_t pm_matches = 0;
    uint8_t cnt;
    uint16_t searchlen;

    if (flags & STREAM_TOSERVER) {
        pm_ctx = &alpd_ctx.ctx_ipp[FlowGetProtoMapping(ipproto)].ctx_pm[0];
        mpm_tctx = &tctx->mpm_tctx[FlowGetProtoMapping(ipproto)][0];
    } else {
        pm_ctx = &alpd_ctx.ctx_ipp[FlowGetProtoMapping(ipproto)].ctx_pm[1];
        mpm_tctx = &tctx->mpm_tctx[FlowGetProtoMapping(ipproto)][1];
    }

    if (pm_ctx->mpm_ctx.pattern_cnt == 0)
        goto end;

    searchlen = buflen;
    if (searchlen > pm_ctx->max_len)
        searchlen = pm_ctx->max_len;

    uint32_t search_cnt = 0;

    /* do the mpm search */
    search_cnt = mpm_table[pm_ctx->mpm_ctx.mpm_type].Search(&pm_ctx->mpm_ctx,
                                                            mpm_tctx,
                                                            &tctx->pmq,
                                                            buf, searchlen);
    if (search_cnt == 0)
        goto end;

    /* alproto bit field */
    uint8_t pm_results_bf[(ALPROTO_MAX / 8) + 1];
    memset(pm_results_bf, 0, sizeof(pm_results_bf));

    for (cnt = 0; cnt < search_cnt; cnt++) {
        AlpdPMSignature *s = pm_ctx->map[tctx->pmq.pattern_id_array[cnt]];
        while (s != NULL) {
            uint16_t proto = AlpdPMMatchSignature(s, buf, searchlen, ipproto);
            if (proto != ALPROTO_UNKNOWN &&
                !(pm_results_bf[proto / 8] & (1 << (proto % 8))) )
                {
                    pm_results[pm_matches++] = proto;
                    pm_results_bf[proto / 8] |= 1 << (proto % 8);
                }
            s = s->next;
        }
    }

 end:
    PmqReset(&tctx->pmq);
    if (buflen >= pm_ctx->max_len)
        FLOW_SET_PM_DONE(f, flags);
    SCReturnUInt(pm_matches);
}
















static AlpdProbingParserPort *AlpdGetProbingParsers(AlpdProbingParser *pp,
                                                    uint16_t ip_proto,
                                                    uint16_t port)
{
    while (pp != NULL) {
        if (pp->ip_proto == ip_proto)
            break;

        pp = pp->next;
    }

    if (pp == NULL)
        return NULL;

    AlpdProbingParserPort *pp_port = pp->port;
    while (pp_port != NULL) {
        if (pp_port->port == port || pp_port->port == 0) {
            break;
        }
        pp_port = pp_port->next;
    }

    return pp_port;
}

/**
 * \brief Call the probing parser if it exists for this src or dst port.
 */
uint16_t AlpdPPGetProto(Flow *f,
                        uint8_t *buf, uint32_t buflen,
                        uint8_t ipproto, uint8_t flags)
{
    AlpdProbingParserPort *pp_port = NULL;
    AlpdProbingParserElement *pe = NULL;
    uint32_t *alproto_masks;

    if (flags & STREAM_TOSERVER) {
        pp_port = AlpdGetProbingParsers(alpd_ctx.ctx_pp, ipproto, f->dp);
        alproto_masks = &f->probing_parser_toserver_alproto_masks;
        if (pp_port == NULL) {
            SCLogDebug("toserver-No probing parser registered for port %"PRIu16,
                       f->dp);
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
        pe = pp_port->toserver;
    } else {
        pp_port = AlpdGetProbingParsers(alpd_ctx.ctx_pp, ipproto, f->sp);
        alproto_masks = &f->probing_parser_toclient_alproto_masks;
        if (pp_port == NULL) {
            SCLogDebug("toclient-No probing parser registered for port %"PRIu16,
                       f->sp);
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
        pe = pp_port->toclient;
    }


    while (pe != NULL) {
        if ((buflen < pe->min_depth)  ||
            (alproto_masks[0] & pe->alproto_mask)) {
            pe = pe->next;
            continue;
        }

        int alproto = pe->ProbingParser(buf, buflen, NULL);
        if (alproto != ALPROTO_UNKNOWN && alproto != ALPROTO_FAILED)
            return alproto;
        if (alproto == ALPROTO_FAILED ||
            (pe->max_depth != 0 && buflen > pe->max_depth)) {
            alproto_masks[0] |= pe->alproto_mask;
        }
        pe = pe->next;
    }

    if (flags & STREAM_TOSERVER) {
        if (alproto_masks[0] == pp_port->toserver_alproto_mask) {
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
    } else {
        if (alproto_masks[0] == pp_port->toclient_alproto_mask) {
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
    }

    return ALPROTO_UNKNOWN;
}













static int AlpdPMSetContentIDs(AlpdPMCtx *ctx)
{
    SCEnter();

    typedef struct TempContainer_ {
        PatIntId id;
        uint16_t content_len;
        uint8_t *content;
    } TempContainer;

    AlpdPMSignature *s = NULL;
    uint32_t struct_total_size = 0;
    uint32_t content_total_size = 0;
    /* array hash buffer */
    uint8_t *ahb = NULL;
    uint8_t *content = NULL;
    uint8_t content_len = 0;
    PatIntId max_id = 0;
    TempContainer *struct_offset = NULL;
    uint8_t *content_offset = NULL;
    TempContainer *dup = NULL;
    int ret = 0;

    if (ctx->head == NULL)
        goto end;

    for (s = ctx->head; s != NULL; s = s->next) {
        struct_total_size += sizeof(TempContainer);
        content_total_size += s->cd->content_len;
    }

    ahb = SCMalloc(sizeof(uint8_t) * (struct_total_size + content_total_size));
    if (unlikely(ahb == NULL))
        goto error;

    struct_offset = (TempContainer *)ahb;
    content_offset = ahb + struct_total_size;
    for (s = ctx->head; s != NULL; s = s->next) {
        dup = (TempContainer *)ahb;
        content = s->cd->content;
        content_len = s->cd->content_len;

        for (; dup != struct_offset; dup++) {
            if (dup->content_len != content_len ||
                SCMemcmp(dup->content, content, dup->content_len) != 0)
                {
                    continue;
                }
            break;
        }

        if (dup != struct_offset) {
            s->cd->id = dup->id;
            continue;
        }

        struct_offset->content_len = content_len;
        struct_offset->content = content_offset;
        content_offset += content_len;
        memcpy(struct_offset->content, content, content_len);
        struct_offset->id = max_id++;
        s->cd->id = struct_offset->id;

        struct_offset++;
    }

    ctx->max_pat_id = max_id;

    goto end;
 error:
    ret = -1;
 end:
    if (ahb != NULL)
        SCFree(ahb);
    SCReturnInt(ret);
}

static int AlpdPMMapSignatures(AlpdPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    PatIntId max_pat_id = 0, tmp_pat_id;
    AlpdPMSignature *s, *next_s;
    int is_ci;
    int mpm_ret;

    max_pat_id = ctx->max_pat_id;

    ctx->map = SCMalloc((max_pat_id) * sizeof(ctx->map));
    if (ctx->map == NULL)
        goto error;
    memset(ctx->map, 0, (max_pat_id) * sizeof(ctx->map));

    for (s = ctx->head; s != NULL;) {
        next_s = s->next;
        s->next = ctx->map[s->cd->id];
        ctx->map[s->cd->id] = s;

        s = next_s;
    }

    for (tmp_pat_id = 0; tmp_pat_id < max_pat_id; tmp_pat_id++) {
        is_ci = 0;
        for (s = ctx->map[tmp_pat_id]; s != NULL; s = s->next) {
            if (s->cd->flags & DETECT_CONTENT_NOCASE) {
                is_ci = 1;
                break;
            }
        }
        if (is_ci) {
            mpm_ret = MpmAddPatternCI(&ctx->mpm_ctx,
                                      s->cd->content, s->cd->content_len,
                                      0, 0,
                                      tmp_pat_id, 0, 0);
            if (mpm_ret < 0)
                goto error;
        } else {
            s = ctx->map[tmp_pat_id];
            mpm_ret = MpmAddPatternCS(&ctx->mpm_ctx,
                                      s->cd->content, s->cd->content_len,
                                      0, 0,
                                      tmp_pat_id, 0, 0);
            if (mpm_ret < 0)
                goto error;
        }
    }

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AlpdPMPrepareMpm(AlpdPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    MpmCtx *mpm_ctx = &ctx->mpm_ctx;

    if (mpm_table[mpm_ctx->mpm_type].Prepare(mpm_ctx) < 0)
        goto error;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}





static int AlpdPMAddSignature(AlpdPMCtx *ctx, DetectContentData *cd,
                              AppProto alproto)
{
    SCEnter();

    int ret = 0;
    AlpdPMSignature *s = SCMalloc(sizeof(*s));
    if (unlikely(s == NULL))
        goto error;
    memset(s, 0, sizeof(*s));

    s->alproto = alproto;
    s->cd = cd;

    /* prepend to the list */
    s->next = ctx->head;
    ctx->head = s;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AlpdPMRegisterPattern(uint16_t ipproto, uint16_t alproto,
                                 char *pattern,
                                 uint16_t depth, uint16_t offset,
                                 uint8_t direction,
                                 uint8_t is_cs)
{
    SCEnter();

    AlpdCtxIpproto *ctx_ipp = &alpd_ctx.ctx_ipp[FlowGetProtoMapping(ipproto)];
    AlpdPMCtx *ctx_pm = NULL;
    DetectContentData *cd;
    int ret = 0;

    cd = DetectContentParseEncloseQuotes(pattern);
    if (cd == NULL)
        goto error;
    cd->depth = depth;
    cd->offset = offset;
    if (!is_cs)
        cd->flags |= DETECT_CONTENT_NOCASE;
    if (depth < cd->content_len)
        goto error;

    if (direction & STREAM_TOSERVER)
        ctx_pm = (AlpdPMCtx *)&ctx_ipp->ctx_pm[0];
    else
        ctx_pm = (AlpdPMCtx *)&ctx_ipp->ctx_pm[1];

    if (depth > ctx_pm->max_len)
        ctx_pm->max_len = depth;
    if (depth < ctx_pm->min_len)
        ctx_pm->min_len = depth;

    /* Finally turn it into a signature and add to the ctx. */
    AlpdPMAddSignature(ctx_pm, cd, alproto);

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}



/***** Public API *****/

int AlpdSetup(void)
{
    SCEnter();

    int i, j;

    memset(&alpd_ctx, 0, sizeof(alpd_ctx));

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            MpmInitCtx(&alpd_ctx.ctx_ipp[i].ctx_pm[j].mpm_ctx, MPM_AC);
        }
    }

    SCReturnInt(0);
}

int AlpdRegisterProtocol(AppProto alproto, char *alproto_name)
{
    SCEnter();

    int ret = 0;

    if (alpd_ctx.alproto_names[alproto] != NULL) {
        SCLogError(SC_ERR_APP_LAYER_PROTOCOL_DETECTION, "App Protocol \"%s("
                   "%"PRIu16")\" already registered for protocol detection.",
                   alproto_name, alproto);
        goto error;
    }
    alpd_ctx.alproto_names[alproto] = alproto_name;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

int AlpdConfProtoDetectionEnabled(const char *alproto)
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
                 alproto, ".enabled");
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

void *AlpdGetCtxThread(void)
{
    SCEnter();

    AlpdCtxThread *alpd_tctx = NULL;
    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int i, j;
    PatIntId max_pat_id = 0;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            if (max_pat_id == 0)
            {
                max_pat_id = alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id;
            } else if (alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id &&
                       max_pat_id < alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id)
            {
                max_pat_id = alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id;
            }
        }
    }

    alpd_tctx = SCMalloc(sizeof(*alpd_tctx));
    if (alpd_tctx == NULL)
        goto error;
    memset(alpd_tctx, 0, sizeof(*alpd_tctx));

    /* Get the max pat id for all the mpm ctxs. */
    if (PmqSetup(&alpd_tctx->pmq, max_pat_id) < 0)
        goto error;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            mpm_ctx = &alpd_ctx.ctx_ipp[i].ctx_pm[j].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[i][j];
            mpm_table[mpm_ctx->mpm_type].InitThreadCtx(mpm_ctx, mpm_tctx, 0);
        }
    }

    goto end;
 error:
    if (alpd_tctx != NULL)
        AlpdDestroyCtxThread(alpd_tctx);
    alpd_tctx = NULL;
 end:
    SCReturnPtr(alpd_tctx, "void *");
}

void AlpdDestroyCtxThread(void *tctx)
{
    SCEnter();

    AlpdCtxThread *alpd_tctx = (AlpdCtxThread *)tctx;
    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int i, j;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            mpm_ctx = &alpd_ctx.ctx_ipp[i].ctx_pm[j].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[i][j];
            mpm_table[mpm_ctx->mpm_type].DestroyThreadCtx(mpm_ctx, mpm_tctx);
        }
    }
    PmqFree(&alpd_tctx->pmq);
    SCFree(alpd_tctx);

    SCReturn;
}

int AlpdPMRegisterPatternCS(uint16_t ipproto, AppProto alproto,
                            char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction)
{
    SCEnter();
    SCReturnInt(AlpdPMRegisterPattern(ipproto, alproto,
                                      pattern,
                                      depth, offset,
                                      direction,
                                      1 /* case-sensitive */));
}

int AlpdPMRegisterPatternCI(uint16_t ipproto, AppProto alproto,
                            char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction)
{
    SCEnter();
    SCReturnInt(AlpdPMRegisterPattern(ipproto, alproto,
                                      pattern,
                                      depth, offset,
                                      direction,
                                      0 /* !case-sensitive */));
}

int AlpdPrepareState(void)
{
    AlpdPMCtx *ctx_pm;
    int i, j;
    int ret = 0;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            ctx_pm = &alpd_ctx.ctx_ipp[i].ctx_pm[j];

            if (AlpdPMSetContentIDs(ctx_pm) < 0)
                goto error;

            if (ctx_pm->max_pat_id == 0)
                continue;

            if (AlpdPMMapSignatures(ctx_pm) < 0)
                goto error;
            if (AlpdPMPrepareMpm(ctx_pm) < 0)
                goto error;
        }
    }

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

AppProto AlpdGetProto(void *tctx,
                      Flow *f,
                      uint8_t *buf, uint32_t buflen,
                      uint8_t ipproto, uint8_t flags)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    uint16_t pm_results[ALPROTO_MAX];
    uint16_t pm_matches;

    if (!FLOW_IS_PM_DONE(f, flags)) {
        pm_matches = AlpdPMGetProto(tctx,
                                    f,
                                    buf, buflen,
                                    flags,
                                    ipproto,
                                    pm_results);
        if (pm_matches > 0)
            return pm_results[0];
    }

    if (!FLOW_IS_PP_DONE(f, flags))
        alproto = AlpdPPGetProto(f, buf, buflen, ipproto, flags);

    return alproto;
}

AppProto AlpdGetProtoByName(char *alproto_name)
{
    AppProto a;

    for (a = 0; a < ALPROTO_MAX; a++) {
        if (alpd_ctx.alproto_names[a] != NULL &&
            strlen(alpd_ctx.alproto_names[a]) == strlen(alproto_name) &&
            (SCMemcmp(alpd_ctx.alproto_names[a], alproto_name, strlen(alproto_name)) == 0))
        {
            return a;
        }
    }

    return ALPROTO_UNKNOWN;
}

char *AlpdGetProtoString(AppProto alproto)
{
    return alpd_ctx.alproto_names[alproto];
}










































/********************************Probing Parsers*******************************/


static uint32_t AlpdProbingParserGetMask(uint16_t alproto)
{
    if (alproto > ALPROTO_UNKNOWN &&
        alproto < ALPROTO_FAILED) {
        return (1 << alproto);
    } else {
        SCLogError(SC_ERR_ALPARSER, "Unknown protocol detected - %"PRIu16,
                   alproto);
        exit(EXIT_FAILURE);
    }
}

static inline AlpdProbingParserElement *AllocAlpdProbingParserElement(void)
{
    AlpdProbingParserElement *p = SCMalloc(sizeof(AlpdProbingParserElement));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AlpdProbingParserElement));

    return p;
}


static inline void DeAllocAlpdProbingParserElement(AlpdProbingParserElement *p)
{
    SCFree(p);
    return;
}

static inline AlpdProbingParserPort *AllocAlpdProbingParserPort(void)
{
    AlpdProbingParserPort *p = SCMalloc(sizeof(AlpdProbingParserPort));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AlpdProbingParserPort));

    return p;
}

static inline void DeAllocAlpdProbingParserPort(AlpdProbingParserPort *p)
{
    AlpdProbingParserElement *e;

    e = p->toserver;
    while (e != NULL) {
        AlpdProbingParserElement *e_next = e->next;
        DeAllocAlpdProbingParserElement(e);
        e = e_next;
    }

    e = p->toclient;
    while (e != NULL) {
        AlpdProbingParserElement *e_next = e->next;
        DeAllocAlpdProbingParserElement(e);
        e = e_next;
    }

    SCFree(p);

    return;
}

static inline AlpdProbingParser *AllocAlpdProbingParser(void)
{
    AlpdProbingParser *p = SCMalloc(sizeof(AlpdProbingParser));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AlpdProbingParser));

    return p;
}

static inline void DeAllocAlpdProbingParser(AlpdProbingParser *p)
{
    AlpdProbingParserPort *pt = p->port;
    while (pt != NULL) {
        AlpdProbingParserPort *pt_next = pt->next;
        DeAllocAlpdProbingParserPort(pt);
        pt = pt_next;
    }

    SCFree(p);

    return;
}

static AlpdProbingParserElement *
AlpdCreateAlpdProbingParserElement(uint16_t alproto,
                                   uint16_t port,
                                   uint16_t min_depth,
                                   uint16_t max_depth,
                                   uint16_t (*AlpdProbingParser)
                                   (uint8_t *input, uint32_t input_len, uint32_t *offset))
{
    AlpdProbingParserElement *pe = AllocAlpdProbingParserElement();

    pe->alproto = alproto;
    pe->port = port;
    pe->alproto_mask = AlpdProbingParserGetMask(alproto);
    pe->min_depth = min_depth;
    pe->max_depth = max_depth;
    pe->ProbingParser = AlpdProbingParser;
    pe->next = NULL;

    if (max_depth != 0 && min_depth >= max_depth) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  min_depth >= max_depth");
        goto error;
    }
    if (alproto <= ALPROTO_UNKNOWN || alproto >= ALPROTO_MAX) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to register "
                   "the probing parser.  Invalid alproto - %d", alproto);
        goto error;
    }
    if (AlpdProbingParser == NULL) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  Probing parser func NULL");
        goto error;
    }

    return pe;
 error:
    DeAllocAlpdProbingParserElement(pe);
    return NULL;
}

static AlpdProbingParserElement *
DuplicateAlpdProbingParserElement(AlpdProbingParserElement *pe)
{
    AlpdProbingParserElement *new_pe = AllocAlpdProbingParserElement();
    if (unlikely(new_pe == NULL)) {
        return NULL;
    }

    new_pe->alproto = pe->alproto;
    new_pe->port = pe->port;
    new_pe->alproto_mask = pe->alproto_mask;
    new_pe->min_depth = pe->min_depth;
    new_pe->max_depth = pe->max_depth;
    new_pe->ProbingParser = pe->ProbingParser;
    new_pe->next = NULL;

    return new_pe;
}

void AlpdPrintProbingParsers(AlpdProbingParser *pp)
{
    AlpdProbingParserPort *pp_port = NULL;
    AlpdProbingParserElement *pp_pe = NULL;

    printf("\n");

    for ( ; pp != NULL; pp = pp->next) {
        /* print ip protocol */
        if (pp->ip_proto == IPPROTO_TCP)
            printf("IPProto: TCP\n");
        else if (pp->ip_proto == IPPROTO_UDP)
            printf("IPProto: UDP\n");
        else
            printf("IPProto: %"PRIu16"\n", pp->ip_proto);

        pp_port = pp->port;
        for ( ; pp_port != NULL; pp_port = pp_port->next) {
            if (pp_port->toserver == NULL)
                goto AlpdPrintProbingParsers_jump_toclient;
            printf("    Port: %"PRIu16 "\n", pp_port->port);

            printf("        To_Server: (max-depth: %"PRIu16 ", "
                   "mask - %"PRIu32")\n",
                   pp_port->toserver_max_depth,
                   pp_port->toserver_alproto_mask);
            pp_pe = pp_port->toserver;
            for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {

                if (pp_pe->alproto == ALPROTO_HTTP)
                    printf("            alproto: ALPROTO_HTTP\n");
                else if (pp_pe->alproto == ALPROTO_FTP)
                    printf("            alproto: ALPROTO_FTP\n");
                else if (pp_pe->alproto == ALPROTO_SMTP)
                    printf("            alproto: ALPROTO_SMTP\n");
                else if (pp_pe->alproto == ALPROTO_TLS)
                    printf("            alproto: ALPROTO_TLS\n");
                else if (pp_pe->alproto == ALPROTO_SSH)
                    printf("            alproto: ALPROTO_SSH\n");
                else if (pp_pe->alproto == ALPROTO_IMAP)
                    printf("            alproto: ALPROTO_IMAP\n");
                else if (pp_pe->alproto == ALPROTO_MSN)
                    printf("            alproto: ALPROTO_MSN\n");
                else if (pp_pe->alproto == ALPROTO_JABBER)
                    printf("            alproto: ALPROTO_JABBER\n");
                else if (pp_pe->alproto == ALPROTO_SMB)
                    printf("            alproto: ALPROTO_SMB\n");
                else if (pp_pe->alproto == ALPROTO_SMB2)
                    printf("            alproto: ALPROTO_SMB2\n");
                else if (pp_pe->alproto == ALPROTO_DCERPC)
                    printf("            alproto: ALPROTO_DCERPC\n");
                else if (pp_pe->alproto == ALPROTO_IRC)
                    printf("            alproto: ALPROTO_IRC\n");
                else
                    printf("impossible\n");

                printf("            port: %"PRIu16 "\n", pp_pe->port);
                printf("            mask: %"PRIu32 "\n", pp_pe->alproto_mask);
                printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                printf("\n");
            }

        AlpdPrintProbingParsers_jump_toclient:
            if (pp_port->toclient == NULL) {
                continue;
            }

            printf("        To_Client: (max-depth: %"PRIu16 ", "
                   "mask - %"PRIu32")\n",
                   pp_port->toclient_max_depth,
                   pp_port->toclient_alproto_mask);
            pp_pe = pp_port->toclient;
            for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {

                if (pp_pe->alproto == ALPROTO_HTTP)
                    printf("            alproto: ALPROTO_HTTP\n");
                else if (pp_pe->alproto == ALPROTO_FTP)
                    printf("            alproto: ALPROTO_FTP\n");
                else if (pp_pe->alproto == ALPROTO_SMTP)
                    printf("            alproto: ALPROTO_SMTP\n");
                else if (pp_pe->alproto == ALPROTO_TLS)
                    printf("            alproto: ALPROTO_TLS\n");
                else if (pp_pe->alproto == ALPROTO_SSH)
                    printf("            alproto: ALPROTO_SSH\n");
                else if (pp_pe->alproto == ALPROTO_IMAP)
                    printf("            alproto: ALPROTO_IMAP\n");
                else if (pp_pe->alproto == ALPROTO_MSN)
                    printf("            alproto: ALPROTO_MSN\n");
                else if (pp_pe->alproto == ALPROTO_JABBER)
                    printf("            alproto: ALPROTO_JABBER\n");
                else if (pp_pe->alproto == ALPROTO_SMB)
                    printf("            alproto: ALPROTO_SMB\n");
                else if (pp_pe->alproto == ALPROTO_SMB2)
                    printf("            alproto: ALPROTO_SMB2\n");
                else if (pp_pe->alproto == ALPROTO_DCERPC)
                    printf("            alproto: ALPROTO_DCERPC\n");
                else if (pp_pe->alproto == ALPROTO_IRC)
                    printf("            alproto: ALPROTO_IRC\n");
                else
                    printf("impossible\n");

                printf("            port: %"PRIu16 "\n", pp_pe->port);
                printf("            mask: %"PRIu32 "\n", pp_pe->alproto_mask);
                printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                printf("\n");
            }
        }
    }

    return;
}

static inline void AppendAlpdProbingParserElement(AlpdProbingParserElement **head_pe,
                                                      AlpdProbingParserElement *new_pe)
{
    if (*head_pe == NULL) {
        *head_pe = new_pe;
        return;
    }

    if ((*head_pe)->port == 0) {
        if (new_pe->port != 0) {
            new_pe->next = *head_pe;
            *head_pe = new_pe;
        } else {
            AlpdProbingParserElement *temp_pe = *head_pe;
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        }
    } else {
        AlpdProbingParserElement *temp_pe = *head_pe;
        if (new_pe->port == 0) {
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        } else {
            while (temp_pe->next != NULL && temp_pe->next->port != 0)
                temp_pe = temp_pe->next;
            new_pe->next = temp_pe->next;
            temp_pe->next = new_pe;

        }
    }

    return;
}

static inline void AppendAlpdProbingParser(AlpdProbingParser **head_pp,
                                               AlpdProbingParser *new_pp)
{
    if (*head_pp == NULL) {
        *head_pp = new_pp;
        return;
    }

    AlpdProbingParser *temp_pp = *head_pp;
    while (temp_pp->next != NULL)
        temp_pp = temp_pp->next;
    temp_pp->next = new_pp;

    return;
}

static inline void AppendAlpdProbingParserPort(AlpdProbingParserPort **head_port,
                                                   AlpdProbingParserPort *new_port)
{
    if (*head_port == NULL) {
        *head_port = new_port;
        return;
    }

    if ((*head_port)->port == 0) {
        new_port->next = *head_port;
        *head_port = new_port;
    } else {
        AlpdProbingParserPort *temp_port = *head_port;
        while (temp_port->next != NULL && temp_port->next->port != 0) {
            temp_port = temp_port->next;
        }
        new_port->next = temp_port->next;
        temp_port->next = new_port;
    }

    return;
}

static inline void AlpdInsertNewProbingParser(AlpdProbingParser **pp,
                                              uint16_t ip_proto,
                                              uint16_t port,
                                              uint16_t alproto,
                                              uint16_t min_depth, uint16_t max_depth,
                                              uint8_t flags,
                                              ProbingParserFPtr ProbingParser)
{
    /* get the top level ipproto pp */
    AlpdProbingParser *curr_pp = *pp;
    while (curr_pp != NULL) {
        if (curr_pp->ip_proto == ip_proto)
            break;
        curr_pp = curr_pp->next;
    }
    if (curr_pp == NULL) {
        AlpdProbingParser *new_pp = AllocAlpdProbingParser();
        new_pp->ip_proto = ip_proto;
        AppendAlpdProbingParser(pp, new_pp);
        curr_pp = new_pp;
    }

    /* get the top level port pp */
    AlpdProbingParserPort *curr_port = curr_pp->port;
    while (curr_port != NULL) {
        if (curr_port->port == port)
            break;
        curr_port = curr_port->next;
    }
    if (curr_port == NULL) {
        AlpdProbingParserPort *new_port = AllocAlpdProbingParserPort();
        new_port->port = port;
        AppendAlpdProbingParserPort(&curr_pp->port, new_port);
        curr_port = new_port;
        if (flags & STREAM_TOSERVER) {
            curr_port->toserver_max_depth = max_depth;
        } else {
            curr_port->toclient_max_depth = max_depth;
        } /* else - if (flags & STREAM_TOSERVER) */

        AlpdProbingParserPort *zero_port;

        zero_port = curr_pp->port;
        while (zero_port != NULL && zero_port->port != 0) {
            zero_port = zero_port->next;
        }
        if (zero_port != NULL) {
            AlpdProbingParserElement *zero_pe;

            zero_pe = zero_port->toserver;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->toserver == NULL)
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                if (curr_port->toserver_max_depth != 0 &&
                    curr_port->toserver_max_depth < zero_pe->max_depth) {
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                }

                                AlpdProbingParserElement *dup_pe =
                                    DuplicateAlpdProbingParserElement(zero_pe);
                                AppendAlpdProbingParserElement(&curr_port->toserver, dup_pe);
                                curr_port->toserver_alproto_mask |= dup_pe->alproto_mask;
            }

            zero_pe = zero_port->toclient;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->toclient == NULL)
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                if (curr_port->toclient_max_depth != 0 &&
                    curr_port->toclient_max_depth < zero_pe->max_depth) {
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                }

                                AlpdProbingParserElement *dup_pe =
                                    DuplicateAlpdProbingParserElement(zero_pe);
                                AppendAlpdProbingParserElement(&curr_port->toclient, dup_pe);
                                curr_port->toclient_alproto_mask |= dup_pe->alproto_mask;
            }
        } /* if (zero_port != NULL) */
    } /* if (curr_port == NULL) */

    /* insert the pe_pp */
    AlpdProbingParserElement *curr_pe;
    if (flags & STREAM_TOSERVER)
        curr_pe = curr_port->toserver;
    else
        curr_pe = curr_port->toclient;
    while (curr_pe != NULL) {
        if (curr_pe->alproto == alproto) {
            SCLogError(SC_ERR_ALPARSER, "Duplicate pp registered - "
                       "ip_proto - %"PRIu16" Port - %"PRIu16" "
                       "App Protocol - NULL, App Protocol(ID) - "
                       "%"PRIu16" min_depth - %"PRIu16" "
                       "max_dept - %"PRIu16".",
                       ip_proto, port, alproto,
                       min_depth, max_depth);
            goto error;
        }
        curr_pe = curr_pe->next;
    }
    /* Get a new parser element */
        AlpdProbingParserElement *new_pe =
            AlpdCreateAlpdProbingParserElement(alproto,
                                                   curr_port->port,
                                                   min_depth, max_depth,
                                                   ProbingParser);
        if (new_pe == NULL)
            goto error;
        curr_pe = new_pe;
        AlpdProbingParserElement **head_pe;
        if (flags & STREAM_TOSERVER) {
            if (curr_port->toserver == NULL)
                curr_port->toserver_max_depth = new_pe->max_depth;
            if (new_pe->max_depth == 0)
                curr_port->toserver_max_depth = new_pe->max_depth;
            if (curr_port->toserver_max_depth != 0 &&
                curr_port->toserver_max_depth < new_pe->max_depth) {
                curr_port->toserver_max_depth = new_pe->max_depth;
            }
            curr_port->toserver_alproto_mask |= new_pe->alproto_mask;
            head_pe = &curr_port->toserver;
        } else {
            if (curr_port->toclient == NULL)
                curr_port->toclient_max_depth = new_pe->max_depth;
            if (new_pe->max_depth == 0)
                curr_port->toclient_max_depth = new_pe->max_depth;
            if (curr_port->toclient_max_depth != 0 &&
                curr_port->toclient_max_depth < new_pe->max_depth) {
                curr_port->toclient_max_depth = new_pe->max_depth;
            }
            curr_port->toclient_alproto_mask |= new_pe->alproto_mask;
            head_pe = &curr_port->toclient;
        }
        AppendAlpdProbingParserElement(head_pe, new_pe);

        if (curr_port->port == 0) {
            AlpdProbingParserPort *temp_port = curr_pp->port;
            while (temp_port != NULL && temp_port->port != 0) {
                if (flags & STREAM_TOSERVER) {
                    if (temp_port->toserver == NULL)
                        temp_port->toserver_max_depth = curr_pe->max_depth;
                    if (curr_pe->max_depth == 0)
                        temp_port->toserver_max_depth = curr_pe->max_depth;
                    if (temp_port->toserver_max_depth != 0 &&
                        temp_port->toserver_max_depth < curr_pe->max_depth) {
                        temp_port->toserver_max_depth = curr_pe->max_depth;
                    }
                    AppendAlpdProbingParserElement(&temp_port->toserver,
                                                       DuplicateAlpdProbingParserElement(curr_pe));
                    temp_port->toserver_alproto_mask |= curr_pe->alproto_mask;
                } else {
                    if (temp_port->toclient == NULL)
                        temp_port->toclient_max_depth = curr_pe->max_depth;
                    if (curr_pe->max_depth == 0)
                        temp_port->toclient_max_depth = curr_pe->max_depth;
                    if (temp_port->toclient_max_depth != 0 &&
                        temp_port->toclient_max_depth < curr_pe->max_depth) {
                        temp_port->toclient_max_depth = curr_pe->max_depth;
                    }
                    AppendAlpdProbingParserElement(&temp_port->toclient,
                                                       DuplicateAlpdProbingParserElement(curr_pe));
                    temp_port->toclient_alproto_mask |= curr_pe->alproto_mask;
                }
                temp_port = temp_port->next;
            } /* while */
        } /* if */

 error:
        return;
}








void AlpdPPRegister(uint16_t ipproto,
                    char *portstr,
                    uint16_t alproto,
                    uint16_t min_depth, uint16_t max_depth,
                    uint8_t flags,
                    ProbingParserFPtr ProbingParser)
{
    DetectPort *head = NULL;
    DetectPortParse(&head, portstr);
    DetectPort *temp_dp = head;
    while (temp_dp != NULL) {
        uint32_t port = temp_dp->port;
        if (port == 0 && temp_dp->port2 != 0)
            port++;
        for ( ; port <= temp_dp->port2; port++) {
            AlpdInsertNewProbingParser(&alpd_ctx.ctx_pp,
                                       ipproto,
                                       port,
                                       alproto,
                                       min_depth, max_depth,
                                       flags,
                                       ProbingParser);
        }
        temp_dp = temp_dp->next;
    }
    DetectPortCleanupList(head);

    return;
}

void AlpdPPParseConfPorts(const char *alproto_name,
                          AppProto alproto,
                          uint16_t min_depth, uint16_t max_depth,
                          ProbingParserFPtr ProbingParser)
{
    char param[100];
    uint8_t ip_proto;
    DetectProto dp;
    int r;
    ConfNode *node;
    ConfNode *proto_node = NULL;
    ConfNode *port_node = NULL;

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto_name, ".detection-ports");
    if (r < 0) {
        SCLogError(SC_ERR_FATAL, "snprintf failure.");
        exit(EXIT_FAILURE);
    } else if (r > (int)sizeof(param)) {
        SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
        exit(EXIT_FAILURE);
    }
    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogDebug("Entry for %s not found.", param);
        return;
    }

    /* for each proto */
    TAILQ_FOREACH(proto_node, &node->head, next) {
        memset(&dp, 0, sizeof(dp));
        r = DetectProtoParse(&dp, proto_node->name);
        if (r < 0) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                       "%s.%s.  Accepted values are tcp, udp and sctp",
                       param, proto_node->name);
            exit(EXIT_FAILURE);
        }
        if (dp.proto[IPPROTO_TCP / 8] & (1 << (IPPROTO_TCP % 8))) {
            ip_proto = IPPROTO_TCP;
        } else if (dp.proto[IPPROTO_UDP / 8] & (1 << (IPPROTO_UDP % 8))) {
            ip_proto = IPPROTO_UDP;
        } else if (dp.proto[IPPROTO_SCTP / 8] & (1 << (IPPROTO_SCTP % 8))) {
            ip_proto = IPPROTO_SCTP;
        } else {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                       "%s.%s.  Accepted values are tcp, udp and sctp",
                       param, proto_node->name);
            exit(EXIT_FAILURE);
        }

        /* toserver */
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto_name, ".detection-ports.", proto_node->name, ".toserver");
        if (r < 0) {
            SCLogError(SC_ERR_FATAL, "snprintf failure.");
            exit(EXIT_FAILURE);
        } else if (r > (int)sizeof(param)) {
            SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
            exit(EXIT_FAILURE);
        }
        port_node = ConfGetNode(param);
        if (port_node != NULL && port_node->val != NULL) {
            AlpdPPRegister(ip_proto,
                           port_node->val,
                           alproto,
                           min_depth, max_depth,
                           STREAM_TOSERVER,
                           ProbingParser);
        }

        /* toclient */
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto_name, ".detection-ports.", proto_node->name, ".toclient");
        if (r < 0) {
            SCLogError(SC_ERR_FATAL, "snprintf failure.");
            exit(EXIT_FAILURE);
        } else if (r > (int)sizeof(param)) {
            SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
            exit(EXIT_FAILURE);
        }
        port_node = ConfGetNode(param);
        if (port_node != NULL && port_node->val != NULL) {
            AlpdPPRegister(ip_proto,
                           port_node->val,
                           alproto,
                           min_depth, max_depth,
                           STREAM_TOCLIENT,
                           ProbingParser);

        }
    }

    return;
}

static void AlpdPMGetIpprotos(AppProto alproto,
                              uint8_t *ipprotos)
{
    SCEnter();

    AlpdPMSignature *s;
    int pat_id, max_pat_id;

    int i, j;
    uint16_t ipproto;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        ipproto = FlowGetReverseProtoMapping(i);
        for (j = 0; j < 2; j++) {
            AlpdPMCtx *pm_ctx = &alpd_ctx.ctx_ipp[i].ctx_pm[j];
            max_pat_id = pm_ctx->max_pat_id;

            for (pat_id = 0; pat_id < max_pat_id; pat_id++) {
                s = pm_ctx->map[pat_id];
                while (s != NULL) {
                    if (s->alproto == alproto)
                        ipprotos[ipproto / 8] |= 1 << (ipproto % 8);
                    s = s->next;
                }
            }
        }
    }

    SCReturn;
}

static void AlpdPPGetIpprotos(AppProto alproto,
                              uint8_t *ipprotos)
{
    SCEnter();

    AlpdProbingParser *pp;
    AlpdProbingParserPort *pp_port;
    AlpdProbingParserElement *pp_pe;

    for (pp = alpd_ctx.ctx_pp; pp != NULL; pp = pp->next) {
        for (pp_port = pp->port; pp_port != NULL; pp_port = pp_port->next) {
            for (pp_pe = pp_port->toserver; pp_pe != NULL; pp_pe = pp_pe->next) {
                if (alproto == pp_pe->alproto)
                    ipprotos[pp->ip_proto / 8] |= 1 << (pp->ip_proto % 8);
            }
            for (pp_pe = pp_port->toclient; pp_pe != NULL; pp_pe = pp_pe->next) {
                if (alproto == pp_pe->alproto)
                    ipprotos[pp->ip_proto / 8] |= 1 << (pp->ip_proto % 8);
            }
        }
    }

    SCReturn;
}

void AlpdSupportedIpprotos(AppProto alproto, uint8_t *ipprotos)
{
    SCEnter();

    AlpdPMGetIpprotos(alproto, ipprotos);
    AlpdPPGetIpprotos(alproto, ipprotos);

    SCReturn;
}


void AlpdRegisterTests(void);
