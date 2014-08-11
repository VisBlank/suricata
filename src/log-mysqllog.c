/*
 * Current log format is too simple, we need json that easy to parse
 *
 * \author coanor <coanor@gmail.com>
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "output.h"

#include "util-debug.h"
#include "util-proto-name.h"
#include "util-time.h"
#include "util-logopenfile.h"
#include "util-print.h"
#include "util-error.h"

#include "app-layer-mysql-common.h"

#include <jansson.h>

static char module_name[] = "LogMysql";
static char log_node_name[] = "mysql-log";
static char log_file_name[] = "mysql.log";

typedef struct LogMysqlFileCtx_ {
    LogFileCtx *ctx;
    uint32_t flags;
} LogMysqlFileCtx;

typedef struct LogMysqlLogThread_ {
    LogMysqlFileCtx *mysqllog_ctx;
    uint32_t mysql_cnt;
} LogMysqlLogThread;

static TmEcode LogMysqlLogThreadInit(ThreadVars *t, void *initdata, void **data) {
    SCEnter();
    (void) t;

    if (!initdata) {
        SCLogDebug("Error getting context for MysqlLog, \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    LogMysqlLogThread *lt = SCCalloc(sizeof(*lt), 1);
    if (unlikely(lt == NULL))
        return TM_ECODE_FAILED;

    lt->mysqllog_ctx = ((OutputCtx *)initdata)->data;
    *data = lt;

    return TM_ECODE_OK;
}

static void LogMysqlLogExitPrintStats(ThreadVars *t, void *data) {
    SCEnter();
    LogMysqlLogThread *lt = data;
    if (!lt)
        return;
    SCLogInfo("Mysql Logger logged %" PRIu32 " transections", lt->mysql_cnt);
}

static TmEcode LogMysqlLogThreadDeinit(ThreadVars *t, void *data) {
    SCEnter();
    LogMysqlLogThread *lt = data;
    if (!lt)
        return TM_ECODE_OK;
    SCFree(lt);
    return TM_ECODE_OK;
}

static int LogMysqlLogger(ThreadVars *tv,
        void *data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id) {

    SCEnter();
    MysqlState *s = state;
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    int ipproto = 0;
    if (PKT_IS_IPV4(p))
        ipproto = AF_INET;
    else if (PKT_IS_IPV6(p))
        ipproto = AF_INET6;

    char srcip[46], dstip[46];
    Port sp, dp;

    if ((PKT_IS_TOCLIENT(p))) {
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
        sp = p->dp;
        dp = p->sp;
    }

    json_t *root = json_object();
    json_object_set_new(root, "time", json_string(timebuf));
    json_object_set_new(root, "src_ip", json_string(srcip));
    json_object_set_new(root, "src_port", json_integer(sp));
    json_object_set_new(root, "dst_ip", json_string(dstip));
    json_object_set_new(root, "dst_port", json_integer(dp));
    json_object_set_new(root, "db_type", json_string((char *)s->protocol_name));
    json_object_set_new(root, "user", json_string(s->cli.username));
    json_object_set_new(root, "db_name", json_string(s->cli.db_name));
    json_object_set_new(root, "action", json_string("PASS")); /* FIXME: this is only the default value */

    json_t *meta_info = json_object();
    json_object_set_new(meta_info, "cmd", json_string(CmdStr(s->cur_tx->cmd)));
    json_object_set_new(meta_info, "sql", json_string(s->cur_tx->sql));
    json_object_set_new(root, "meta_info", meta_info);

    LogMysqlLogThread *lt = data;
    SCMutexLock(&lt->mysqllog_ctx->ctx->fp_mutex);
    int ret = json_dumpf(root, lt->mysqllog_ctx->ctx->fp, JSON_COMPACT);
    if (ret) {
        SCLogError(SC_ERR_JSON_DUMP_FAILED, "dump json failed");
    }
    fflush(lt->mysqllog_ctx->ctx->fp);
    SCMutexUnlock(&lt->mysqllog_ctx->ctx->fp_mutex);

    json_decref(root);

end:
    return 0;
}

static void LogMysqlLogDeinitCtx(OutputCtx *ctx) {
    SCEnter();
    LogMysqlFileCtx *mysqllog_ctx = (LogMysqlFileCtx *)ctx->data;
    LogFileFreeCtx(mysqllog_ctx->ctx);
    SCFree(mysqllog_ctx);
    SCFree(ctx);
}

static OutputCtx *LogMysqlInitCtx(ConfNode *cn) {
    SCEnter();
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (!file_ctx) {
        SCLogError(SC_ERR_MYSQL_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(cn, file_ctx, log_file_name) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogMysqlFileCtx *mysqllog_ctx = SCMalloc(sizeof(*mysqllog_ctx));
    if (!mysqllog_ctx) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    memset(mysqllog_ctx, 0, sizeof(*mysqllog_ctx));
    mysqllog_ctx->ctx = file_ctx;

    OutputCtx *octx = SCCalloc(1, sizeof(*octx));
    if (!octx) {
        LogFileFreeCtx(file_ctx);
        SCFree(mysqllog_ctx);
        return NULL;
    }

    octx->data = mysqllog_ctx;
    octx->DeInit = LogMysqlLogDeinitCtx;

    SCLogDebug("Mysql log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);
    return octx;
}

void TmModuleLogMysqlRegister(void) {
    SCEnter();
    tmm_modules[TMM_LOGMYSQLLOG].name = module_name;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadInit = LogMysqlLogThreadInit;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadExitPrintStats = LogMysqlLogExitPrintStats;
    tmm_modules[TMM_LOGMYSQLLOG].ThreadDeinit = LogMysqlLogThreadDeinit;
    tmm_modules[TMM_LOGMYSQLLOG].cap_flags = 0;
    tmm_modules[TMM_LOGMYSQLLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGMYSQLLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(module_name, log_node_name, LogMysqlInitCtx,
            ALPROTO_MYSQL, LogMysqlLogger);
}
