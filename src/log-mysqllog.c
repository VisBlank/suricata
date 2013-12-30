#include "suricata-common.h"
#include "debug.h"
#include "conf.h"
#include "util-print.h"
#include "util-debug.h"
#include "output.h"
#include "log-mysqllog.h"
#include "app-layer.h"
#include "util-logopenfile.h"

#define MODULE_NAME "LogMysqlLog"
#define DEFAULT_LOG_FILENAME "mysql.log"

typedef struct LogMysqlLogThread_ {
    LogFileCtx *file_ctx;
    uint32_t mysql_cnt;
} LogMysqlLogThread;

TmEcode LogMysqlLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogMysqlLogThreadDeinit(ThreadVars *, void *);
OutputCtx *LogMysqlLogInitCtx(ConfNode *conf);
TmEcode LogMysqlLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);
void LogMysqlLogExitPrintStats(ThreadVars *tv, void *data);
static void LogMysqlDeinitCtx(OutputCtx *ctx);

void TmModuleLogMysqlRegister(void) {
    tmm_modules[TMM_LOGMYSQLLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadInit = LogMysqlLogThreadInit;
    tmm_modules[TMM_LOGMYSQLLOG].Func = LogMysqlLog;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadExitPrintStats = LogMysqlLogExitPrintStats;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadDeinit = LogMysqlLogThreadDeinit;
    tmm_modules[TMM_LOGMYSQLLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGMYSQLLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "mysql-log", LogMysqlLogInitCtx);

    SCLogDebug("registered %s", MODULE_NAME);
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

    mlt->file_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)mlt;
    return TM_ECODE_OK;
}

TmEcode LogMysqlLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    /* TODO */
    return TM_ECODE_OK;
}


TmEcode LogMysqlLogThreadDeinit(ThreadVars *t, void *data) {
    /* TODO */
    return TM_ECODE_OK;
}

void LogMysqlLogExitPrintStats(ThreadVars *tv, void *data) {
    /* TODO */
}

OutputCtx *LogMysqlLogInitCtx(ConfNode *conf) {
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_MYSQL_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
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
    AppLayerRegisterLogger(ALPROTO_MYSQL);
    return output_ctx;
}

static void LogMysqlDeinitCtx(OutputCtx *ctx) {
    LogFileFreeCtx(ctx->data);
    SCFree(ctx);
}
