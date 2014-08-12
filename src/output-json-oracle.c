/*
 * json output for Oracle event
 * date: Thu May 15 14:25:03 CST 2014
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
#include "app-layer-oracle11g-common.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogOracleFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogOracleFileCtx;

typedef struct LogOracleLogThread_ {
    LogOracleFileCtx *oraclelog_ctx;
    uint32_t cnt;
    MemBuffer *buffer;
} LogOracleLogThread;

static const int output_buffer_size = 65536;

static TmEcode Oracle11gJsonLogThreadInit(ThreadVars *t, void *initdata, void **data) {
    if (!initdata) {
        SCLogDebug("Error getting context for Oracle log.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    LogOracleLogThread *aft = SCCalloc(sizeof(*aft), 1);
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    aft->buffer = MemBufferCreateNew(output_buffer_size);
    if (!aft->buffer) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->oraclelog_ctx = ((OutputCtx *)initdata)->data;
    *data = aft;
    return TM_ECODE_OK;
}

static TmEcode OracleJsonLogThreadDeinit(ThreadVars *t, void *data) {
    LogOracleLogThread *aft = data;
    if (!aft)
        return TM_ECODE_OK;
    MemBufferFree(aft->buffer);
    memset(aft, 0, sizeof(LogOracleLogThread));
    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogOracleLogDeinitCtx(OutputCtx *ctx) {
    LogOracleFileCtx *oraclelog_ctx = ctx->data;
    LogFileFreeCtx(oraclelog_ctx->file_ctx);
    SCFree(oraclelog_ctx);
    SCFree(ctx);
}

static OutputCtx *JsonOracle11gLogInitCtx(ConfNode *cn) {
    static char default_11g_log_filename[] = "oracle11g.json";
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (!file_ctx) {
        SCLogError(SC_ERR_ORACLE_11G_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(cn, file_ctx, default_11g_log_filename)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogOracleFileCtx *oraclelog_ctx = SCCalloc(sizeof(*oraclelog_ctx), 1);
    if (unlikely(!oraclelog_ctx )) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    oraclelog_ctx->file_ctx = file_ctx;
    OutputCtx *octx = SCCalloc(1, sizeof(*octx));
    if (unlikely(!octx)) {
        LogFileFreeCtx(file_ctx);
        SCFree(oraclelog_ctx);
        return NULL;
    }

    octx->data = oraclelog_ctx;
    octx->DeInit = LogOracleLogDeinitCtx;

    SCLogDebug("Oracle json log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_ORACLE11G);
    return octx;
}

static int JsonOracle11gLogger(ThreadVars *t, void *thread_data,
        const Packet *p, Flow *f, void *alstate,
        void *txptr, uint64_t tx_id) {
    SCEnter();
    LogOracleLogThread *td = thread_data;
    Oracle11gState *s = alstate;
    Oracle11gTransaction *tx = txptr;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "oracle11g");
    if (unlikely(!js))
        return TM_ECODE_FAILED;

    json_t *djs = json_object();
    if (unlikely(!djs))
        return TM_ECODE_FAILED;

    json_object_set_new(js, "oracle11g", djs);

    MemBuffer *buffer = td->buffer;
    MemBufferReset(buffer);

    if (!s->conn_data)
        return 0;

    json_object_set_new(djs, "user", json_string(s->conn_data->user));
    /* XXX: is sid equal to dbname in Oracle? */
    json_object_set_new(djs, "db_name", json_string(s->conn_data->sid));

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

    json_object_set_new(meta_info, "sql", tx->sql ? json_string((const char *)tx->sql) : json_null());
    switch (tx->tx_type) {
    case oracle11g_tx_type_try_login:  
        json_object_set_new(meta_info, "cmd", json_string("login"));
        break;
    case oracle11g_tx_type_sql_query:
        json_object_set_new(meta_info, "cmd", json_string("query"));
        break;
    case oracle11g_tx_type_disconnect:
        json_object_set_new(meta_info, "cmd", json_string("disconnect"));
        break;
    default:
        json_object_set_new(meta_info, "cmd", json_string("unkonw"));
        break;
    }

    OutputJSONBuffer(js, td->oraclelog_ctx->file_ctx, buffer);
    json_object_del(djs, "meta_info");
    json_object_del(djs, "oracle");

    json_decref(js);
    SCReturnInt(TM_ECODE_OK);
}

static char module_name_11g[] = "JsonOracle11gLog";
void TmModuleJsonOracle11gLogRegister(void) {
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].name = module_name_11g;
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].ThreadInit = Oracle11gJsonLogThreadInit;
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].ThreadDeinit = OracleJsonLogThreadDeinit;
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].RegisterTests = NULL;
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].cap_flags = 0;
    tmm_modules[TMM_JSON_ORACLE_11G_LOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(module_name_11g, "oracle11g-json-log", JsonOracle11gLogInitCtx,
            ALPROTO_ORACLE11G, JsonOracle11gLogger);
}
#endif
