/**
 * \file
 * \auth
 * Tue Jan 21 14:01:21 CST 2014
 */

#include "suricata-common.h"
#include "debug.h"
#include "conf.h"
#include "util-print.h"
#include "util-debug.h"
#include "log-tdslog.h"
#include "app-layer.h"
#include "util-logopenfile.h"
#include "util-buffer.h"
#include "util-json.h"
#include "decode.h"
#include "output.h"
#include "app-layer-tds-common.h"

#define OUTPUT_TDS_MODULE_NAME "LogTDSLog"
#define OUTPUT_TDS_DEFAULT_LOG_FILENAME "tds.log"
#define OUTPUT_TDS_BUFFER_SIZE 65535

typedef struct LogTDSLogThread_ {
    LogFileCtx *ctx;
    uint32_t flags; /* store mode */
    uint32_t log_cnt;
    MemBuffer *buffer;
} LogTDSLogThread;

TmEcode LogTDSLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogTDSLogThreadDeinit(ThreadVars *, void *);
OutputCtx *LogTDSLogInitCtx(ConfNode *conf);
TmEcode LogTDSLog(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);
void LogTDSLogExitPrintStats(ThreadVars *tv, void *data);
static void LogTDSDeinitCtx(OutputCtx *ctx);
TmEcode LogTDSLogIPV4(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);
TmEcode LogTDSLogIPV6(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);

void TmModuleLogTDSRegister(void) {
    tmm_modules[TMM_LOGTDSLOG].name = OUTPUT_TDS_MODULE_NAME;
    tmm_modules[TMM_LOGTDSLOG].ThreadInit = LogTDSLogThreadInit;
    tmm_modules[TMM_LOGTDSLOG].Func = LogTDSLog;
    tmm_modules[TMM_LOGTDSLOG].ThreadExitPrintStats = LogTDSLogExitPrintStats;
    tmm_modules[TMM_LOGTDSLOG].ThreadDeinit = LogTDSLogThreadDeinit;
    tmm_modules[TMM_LOGTDSLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGTDSLOG].cap_flags = 0;

    OutputRegisterModule(OUTPUT_TDS_MODULE_NAME, "tds-log", LogTDSLogInitCtx);
    SCLogDebug("registered %s", OUTPUT_TDS_MODULE_NAME);
}

TmEcode LogTDSLogThreadInit(ThreadVars *tv, void *initdata, void **data) {
    LogTDSLogThread *lt = SCMalloc(sizeof(LogTDSLogThread));
    if (unlikely(lt == NULL))
        return TM_ECODE_FAILED;
    memset(lt, 0, sizeof(LogTDSLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for TDSLog.  \"initdata\" argument NULL");
        SCFree(lt);
        return TM_ECODE_FAILED;
    }

    lt->buffer = MemBufferCreateNew(OUTPUT_TDS_BUFFER_SIZE);
    if (lt->buffer == NULL) {
        SCFree(lt);
        return TM_ECODE_FAILED;
    }

    lt->ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)lt;
    return TM_ECODE_OK;
}

TmEcode LogTDSLogThreadDeinit(ThreadVars *tv, void *data) {
    LogTDSLogThread *lt = (LogTDSLogThread *)data;
    if (lt == NULL)
        return TM_ECODE_OK;

    MemBufferFree(lt->buffer);
    memset(lt, 0, sizeof(LogTDSLogThread));

    SCFree(lt);
    return TM_ECODE_OK;
}

OutputCtx *LogTDSLogInitCtx(ConfNode *conf) {
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TDS_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, OUTPUT_TDS_DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return NULL;
    }

    output_ctx->data = file_ctx;
    output_ctx->DeInit = LogTDSDeinitCtx;
  
    SCLogDebug("TDS log output initialized");

    AppLayerRegisterLogger(ALPROTO_TDS);
    return output_ctx;
}

TmEcode LogTDSLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    SCEnter();

    /* no flow, no TDS state */
    if (p->flow == NULL)
        SCReturnInt(TM_ECODE_OK);

    if (!(PKT_IS_TCP(p))) /* only support TCP on TDS */
        SCReturnInt(TM_ECODE_OK);

    if (PKT_IS_IPV4(p))
        SCReturnInt(LogTDSLogIPV4(tv, p, data, pq, postpq));
    else if (PKT_IS_IPV6(p))
        SCReturnInt(LogTDSLogIPV6(tv, p, data, pq, postpq));
    
    SCReturnInt(TM_ECODE_OK);
}

void LogTDSLogExitPrintStats(ThreadVars *tv, void *data) {
    LogTDSLogThread *lt = (LogTDSLogThread *)data;
    if (lt == NULL)
        return;
    SCLogInfo("TDS logger logged %" PRIu32 " requests", lt->log_cnt);
}

static void LogTDSDeinitCtx(OutputCtx *ctx) {
    LogFileFreeCtx(ctx->data);
    SCFree(ctx);
}

TmEcode LogTDSLogIPWrapper(ThreadVars *tv,
        Packet *p,
        void *data,
        PacketQueue *pq,
        PacketQueue *postpq,
        int ipproto);

TmEcode LogTDSLogIPV4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogTDSLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogTDSLogIPV6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogTDSLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogTDSLogIPWrapper(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto)  {
    SCEnter();
    TDSState *s = NULL;
    LogTDSLogThread *lt = (LogTDSLogThread *)data;

    if (p->flow == NULL)
        SCReturnInt(TM_ECODE_OK);

    FLOWLOCK_WRLOCK(p->flow); /* write lock before update flow log id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TDS)
        goto end;

    s = (TDSState *)AppLayerGetProtoStateFromPacket(p);
    if (s == NULL) {
        SCLogDebug("no TDS state, so no request logging");
        goto end;
    }
    
    char timebuf[64];
    char srcip[46], dstip[46];
    Port sp = 0, dp = 0;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        goto end; /* do not log server response */
#if 0
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                break;
            default:
                goto end;
        }
#endif
    }

    uint8_t *json_sql;
    uint8_t *sql = s->cur_tx->cmd.sql;
    if (sql == NULL)
        json_sql = NULL;
    else
        json_sql = prepare_json_str(sql, s->cur_tx->cmd.sql_size);

    MemBufferReset(lt->buffer);
    MemBufferWriteString(lt->buffer,
            "{time:%s,src_ip:'%s',src_port:%d,dst_ip:'%s',dst_port:%d,"
            "db_type:'%s',user:'%s',db_name:'%s',operation:'%s', action:'%s',"
            "meta_info:{cmd:'%s',sql:'%s',client_name:'%s',app_name:'%s',library_name:'%s'}},\n",
            timebuf, srcip, sp, dstip, dp,
            "SQL Server",
            s->cur_tx->cli.user_name ? s->cur_tx->cli.user_name : "null",
            s->cur_tx->cli.db_name ? s->cur_tx->cli.db_name : "null",
            TDSCmdStr(s->cur_tx->cmd.tds_cmd),
            "PASS", /* how do I konw it was passed (in detect module) */
            TDSCmdStr(s->cur_tx->cmd.tds_cmd), /* FIXME: the same to operation */
            json_sql ? json_sql : "null",
            s->cur_tx->cli.client_name ? s->cur_tx->cli.client_name: "null",
            s->cur_tx->cli.app_name ? s->cur_tx->cli.app_name: "null",
            s->cur_tx->cli.library_name ? s->cur_tx->cli.library_name: "null");
    SCMutexLock(&lt->ctx->fp_mutex);

    (void)MemBufferPrintToFPAsString(lt->buffer, lt->ctx->fp);
    fflush(lt->ctx->fp);
    SCMutexUnlock(&lt->ctx->fp_mutex);
    AppLayerTransactionUpdateLogId(p->flow);

    if (json_sql)
        SCFree(json_sql);

    /* TODO : add pending packages */

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}
