/**
 * \file
 * \auth
 * Implement mysql logging portion of the engin
 */

#include "suricata-common.h"
#include "debug.h"
#include "conf.h"
#include "util-print.h"
#include "util-debug.h"
#include "output.h"
#include "log-mysqllog.h"
#include "app-layer.h"
//#include "app-layer-mysql.h"
#include "app-layer-mysql-common.h"
#include "util-logopenfile.h"
#include "util-buffer.h"
#include "decode.h"

#define OUTPUT_MYSQL_MODULE_NAME "LogMysqlLog"
#define OUTPUT_MYSQL_DEFAULT_LOG_FILENAME "mysql.json"
#define OUTPUT_MYSQL_BUFFER_SIZE 65535

typedef struct LogMysqlLogThread_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /* store mode */
    uint32_t log_cnt;
    MemBuffer *buffer;
} LogMysqlLogThread;

TmEcode LogMysqlLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogMysqlLogThreadDeinit(ThreadVars *, void *);
OutputCtx *LogMysqlLogInitCtx(ConfNode *conf);
TmEcode LogMysqlLog(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);
void LogMysqlLogExitPrintStats(ThreadVars *tv, void *data);
static void LogMysqlDeinitCtx(OutputCtx *ctx);
TmEcode LogMysqlLogIPV4(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);
TmEcode LogMysqlLogIPV6(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq);

void TmModuleLogMysqlRegister(void) {
    tmm_modules[TMM_LOGMYSQLLOG].name = OUTPUT_MYSQL_MODULE_NAME;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadInit = LogMysqlLogThreadInit;
    tmm_modules[TMM_LOGMYSQLLOG].Func = LogMysqlLog;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadExitPrintStats = LogMysqlLogExitPrintStats;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadDeinit = LogMysqlLogThreadDeinit;
    tmm_modules[TMM_LOGMYSQLLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGMYSQLLOG].cap_flags = 0;

    OutputRegisterModule(OUTPUT_MYSQL_MODULE_NAME, "mysql-log", LogMysqlLogInitCtx);

    SCLogDebug("registered %s", OUTPUT_MYSQL_MODULE_NAME);
}

TmEcode LogMysqlLogThreadInit(ThreadVars *t, void *initdata, void **data) {
    /* TODO */
    LogMysqlLogThread *mlt = SCMalloc(sizeof(LogMysqlLogThread));
    if (unlikely(mlt == NULL))
        return TM_ECODE_FAILED;
    memset(mlt, 0, sizeof(LogMysqlLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for MysqlLog.  \"initdata\" argument NULL");
        SCFree(mlt);
        return TM_ECODE_FAILED;
    }

    mlt->buffer = MemBufferCreateNew(OUTPUT_MYSQL_BUFFER_SIZE);
    if (mlt->buffer == NULL) {
        SCFree(mlt);
        return TM_ECODE_FAILED;
    }

    mlt->file_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)mlt;
    return TM_ECODE_OK;
}

TmEcode LogMysqlLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    SCEnter();

    /* no flow, no mysql state */
    if (p->flow == NULL)
        SCReturnInt(TM_ECODE_OK);

    if (!(PKT_IS_TCP(p))) /* only support TCP on mysql */
        SCReturnInt(TM_ECODE_OK);

    if (PKT_IS_IPV4(p))
        SCReturnInt(LogMysqlLogIPV4(tv, p, data, pq, postpq));
    else if (PKT_IS_IPV6(p))
        SCReturnInt(LogMysqlLogIPV6(tv, p, data, pq, postpq));
    
    SCReturnInt(TM_ECODE_OK);
}


TmEcode LogMysqlLogThreadDeinit(ThreadVars *t, void *data) {
    LogMysqlLogThread *mlt = (LogMysqlLogThread *)data;
    if (mlt == NULL)
        return TM_ECODE_OK;

    MemBufferFree(mlt->buffer);
    memset(mlt, 0, sizeof(LogMysqlLogThread));

    SCFree(mlt);
    return TM_ECODE_OK;
}

void LogMysqlLogExitPrintStats(ThreadVars *tv, void *data) {
    LogMysqlLogThread *mlt = (LogMysqlLogThread *)data;
    if (mlt == NULL)
        return;
    SCLogInfo("MySQL logger logged %" PRIu32 " requests", mlt->log_cnt);
}

OutputCtx *LogMysqlLogInitCtx(ConfNode *conf) {
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_MYSQL_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, OUTPUT_MYSQL_DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return NULL;
    }

    output_ctx->data = file_ctx;
    output_ctx->DeInit = LogMysqlDeinitCtx;
  
    SCLogDebug("Mysql log output initialized");

    AppLayerRegisterLogger(ALPROTO_MYSQL);
    return output_ctx;
}

static void LogMysqlDeinitCtx(OutputCtx *ctx) {
    LogFileFreeCtx(ctx->data);
    SCFree(ctx);
}

TmEcode LogMysqlLogIPWrapper(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto) {
    SCEnter();
    MysqlState *s = NULL;
    LogMysqlLogThread *mlt = (LogMysqlLogThread *)data;
    char timebuf[64];

    if (p->flow == NULL)
        SCReturnInt(TM_ECODE_OK);


    FLOWLOCK_WRLOCK(p->flow); /* write lock before update flow log id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_MYSQL)
        goto end;

    s = (MysqlState *)AppLayerGetProtoStateFromPacket(p);
    if (s == NULL) {
        SCLogDebug("no mysql state, so no request logging");
        goto end;
    }
    
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    char srcip[46], dstip[46];
    Port sp, dp;
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
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
    }

    MemBufferReset(mlt->buffer);
end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogMysqlLogIPV4(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogMysqlLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogMysqlLogIPV6(ThreadVars *tv, Packet *p,
        void *data, PacketQueue *pq, PacketQueue *postpq) {
    return LogMysqlLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}
