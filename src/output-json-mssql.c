/*
 * author: tanb
 * date: Wed Jun 18 14:04:02 CST 2014
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-mssql-common.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogMSSqlFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogMSSqlFileCtx;

typedef struct LogMSSqlLogThread_ {
    LogMSSqlFileCtx *mssqllog_ctx;
    uint32_t cnt;
    MemBuffer *buffer;
} LogMSSqlLogThread;

static const int output_buffer_size = 65536;

static TmEcode MSSqlJsonLogThreadInit(ThreadVars *t, void *initdata, void **data) {
    if (!initdata) {
        SCLogDebug("Error getting context for mssql log.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    LogMSSqlLogThread *aft = SCCalloc(sizeof(*aft), 1);
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    aft->buffer = MemBufferCreateNew(output_buffer_size);
    if (!aft->buffer) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->mssqllog_ctx = ((OutputCtx *)initdata)->data;
    *data = aft;
    return TM_ECODE_OK;
}

static TmEcode MSSqlJsonLogThreadDeinit(ThreadVars *t, void *data) {
    LogMSSqlLogThread *aft = data;
    if (!aft)
        return TM_ECODE_OK;
    MemBufferFree(aft->buffer);
    memset(aft, 0, sizeof(*aft));
    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogMSSqlLogDeinitCtx(OutputCtx *ctx) {
    LogMSSqlFileCtx *mssqllog_ctx = ctx->data;
    LogFileFreeCtx(mssqllog_ctx->file_ctx);
    SCFree(mssqllog_ctx);
    SCFree(ctx);
}

static OutputCtx *JsonMSSqlLogInitCtx(ConfNode *cn) {
    static char default_11g_log_filename[] = "mssql.json";
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (!file_ctx) {
        SCLogError(SC_ERR_MSSQL_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(cn, file_ctx, default_11g_log_filename)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogMSSqlFileCtx *mssqllog_ctx = SCCalloc(sizeof(*mssqllog_ctx), 1);
    if (unlikely(!mssqllog_ctx )) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    mssqllog_ctx->file_ctx = file_ctx;
    OutputCtx *octx = SCCalloc(1, sizeof(*octx));
    if (unlikely(!octx)) {
        LogFileFreeCtx(file_ctx);
        SCFree(mssqllog_ctx);
        return NULL;
    }

    octx->data = mssqllog_ctx;
    octx->DeInit = LogMSSqlLogDeinitCtx;

    SCLogDebug("mssql json log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MSSQL);
    return octx;
}

static int JsonMSSqlLogger(ThreadVars *t, void *thread_data,
        const Packet *p, Flow *f, void *alstate,
        void *txptr, uint64_t tx_id) {
    SCEnter();
    LogMSSqlLogThread *td = thread_data;
    TDSState *s = alstate;
    TDSTransaction *tx = txptr;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "mssql");
    if (unlikely(!js))
        return TM_ECODE_FAILED;

    json_t *djs = json_object();
    if (unlikely(!djs))
        return TM_ECODE_FAILED;

    json_object_set_new(js, "mssql", djs);

    MemBuffer *buffer = td->buffer;
    MemBufferReset(buffer);

    json_object_set_new(djs, "user", json_string((char *)s->cli.user_name));
    json_object_set_new(djs, "db_name", s->cli.db_name ? json_string((char *)s->cli.db_name) : json_null());

    const char *action = NULL;
    switch (tx->action) {
        case ACTION_ALERT:
            action = "ALERT"; break;
        case ACTION_DROP:
            action = "DROP"; break;
        case ACTION_REJECT:
            action = "REJECT"; break;
        case ACTION_PASS:
            action = "PASS"; break;
        default:
            action = "UNKNOWN"; break;
    }

    json_object_set_new(djs, "action", json_string(action));
    json_t *meta_info = json_object();
    if (unlikely(!meta_info))
        return TM_ECODE_FAILED;

    json_object_set_new(djs, "meta_info", meta_info);

    json_object_set_new(meta_info, "sql", tx->sql ? json_string((char *)tx->sql) : json_null());
    switch (tx->tx_type) {
    case tds_tx_type_login:
        json_object_set_new(meta_info, "cmd", json_string("login"));
        break;
    case tds_tx_type_query:
        json_object_set_new(meta_info, "cmd", json_string("query"));
        break;
    default:
        json_object_set_new(meta_info, "cmd", json_string("unkonw"));
        break;
    }

    OutputJSONBuffer(js, td->mssqllog_ctx->file_ctx, buffer);
    json_object_del(djs, "meta_info");
    json_object_del(djs, "mssql");

    json_decref(js);
    SCReturnInt(TM_ECODE_OK);
}

static char module_name[] = "JsonMSSqlLog";
void TmModuleJsonMSSqlLogRegister(void) {
    tmm_modules[TMM_JSON_MSSQL_LOG].name = module_name;
    tmm_modules[TMM_JSON_MSSQL_LOG].ThreadInit = MSSqlJsonLogThreadInit;
    tmm_modules[TMM_JSON_MSSQL_LOG].ThreadDeinit = MSSqlJsonLogThreadDeinit;
    tmm_modules[TMM_JSON_MSSQL_LOG].RegisterTests = NULL;
    tmm_modules[TMM_JSON_MSSQL_LOG].cap_flags = 0;
    tmm_modules[TMM_JSON_MSSQL_LOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(module_name, "mssql-json-log", JsonMSSqlLogInitCtx,
            ALPROTO_MSSQL, JsonMSSqlLogger);
}
#endif /* HAVE_LIBJANSSON */
