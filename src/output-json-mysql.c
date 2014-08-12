/*
 * json output for MySQL event
 * date: Mon Apr 28 09:36:59 CST 2014
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
#include "app-layer-mysql-common.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

static char module_name[] = "JsonMysqlLog";

typedef struct LogMysqlFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogMysqlFileCtx;

typedef struct LogMysqlLogthread_ {
    LogMysqlFileCtx *mysqllog_ctx;
    uint32_t mysql_cnt;
    MemBuffer *buffer;
} LogMysqlLogthread;

static const int output_buffer_size = 65536;
static TmEcode MysqlJsonLogThreadInit(ThreadVars *t, void *initdata, void **data) {
    if (!initdata) {
        SCLogDebug("Error getting context for Mysql log.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    LogMysqlLogthread *aft = SCCalloc(sizeof(*aft), 1);
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    aft->buffer = MemBufferCreateNew(output_buffer_size);
    if (!aft->buffer) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->mysqllog_ctx = ((OutputCtx *)initdata)->data;
    *data = aft;
    return TM_ECODE_OK;
}

static TmEcode MysqlJsonLogThreadDeinit(ThreadVars *t, void *data) {
    LogMysqlLogthread *aft = data;
    if (!aft)
        return TM_ECODE_OK;
    MemBufferFree(aft->buffer);
    memset(aft, 0, sizeof(LogMysqlLogthread));
    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogMysqlLogDeinitCtx(OutputCtx *ctx) {
    LogMysqlFileCtx *mysqllog_ctx = ctx->data;
    LogFileFreeCtx(mysqllog_ctx->file_ctx);
    SCFree(mysqllog_ctx);
    SCFree(ctx);
}

static int JsonMysqlLogger(ThreadVars *t, void *thread_data,
        const Packet *p, Flow *f, void *alstate,
        void *txptr, uint64_t tx_id) {

    SCEnter();
    LogMysqlLogthread *td = thread_data;
    MysqlState *s = alstate;
    MysqlTransaction *tx = txptr;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "mysql");
    if (unlikely(!js))
        return TM_ECODE_FAILED;

    /* log state or transection ? */
    json_t *djs = json_object();
    if (unlikely(!djs))
        return TM_ECODE_FAILED;

    json_object_set_new(js, "mysql", djs);

    MemBuffer *buffer = td->buffer;
    MemBufferReset(buffer);

    json_object_set_new(djs, "user", json_string(s->cli.username));
    json_object_set_new(djs, "db_name",
            s->cli.db_name ? json_string(s->cli.db_name) : json_null());

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
    if (unlikely(!meta_info)) {
        return TM_ECODE_FAILED; 
    }

    json_object_set_new(djs, "meta_info", meta_info);

    json_object_set_new(meta_info, "cmd", json_string(CmdStr(tx->cmd)));

    json_object_set_new(meta_info, "sql",
            tx->sql ? json_string((const char *)tx->sql):json_null());

    OutputJSONBuffer(js, td->mysqllog_ctx->file_ctx, buffer);

    json_object_del(djs, "meta_info");
    json_object_del(js, "mysql");

    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

static char default_log_filename[] = "mysql.json";

static OutputCtx *JsonMysqlLogInitCtx(ConfNode *cn) {
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (!file_ctx) {
        SCLogError(SC_ERR_MYSQL_LOG_GENERIC, "could not create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(cn, file_ctx, default_log_filename)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogMysqlFileCtx *mysqllog_ctx = SCCalloc(sizeof(*mysqllog_ctx), 1);
    if (unlikely(!mysqllog_ctx)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    mysqllog_ctx->file_ctx = file_ctx;
    OutputCtx *octx = SCCalloc(1, sizeof(*octx));
    if (unlikely(!octx)) {
        LogFileFreeCtx(file_ctx); 
        SCFree(mysqllog_ctx);
        return NULL;
    }

    octx->data = mysqllog_ctx;
    octx->DeInit = LogMysqlLogDeinitCtx;

    SCLogDebug("Mysql json log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);
    return octx;
}

void TmModuleJsonMysqlLogRegister(void) {
    tmm_modules[TMM_JSON_MYSQL_LOG].name = module_name;
    tmm_modules[TMM_JSON_MYSQL_LOG].ThreadInit = MysqlJsonLogThreadInit;
    tmm_modules[TMM_JSON_MYSQL_LOG].ThreadDeinit = MysqlJsonLogThreadDeinit;
    tmm_modules[TMM_JSON_MYSQL_LOG].RegisterTests = NULL;
    tmm_modules[TMM_JSON_MYSQL_LOG].cap_flags = 0;
    tmm_modules[TMM_JSON_MYSQL_LOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(module_name, "mysql-json-log", JsonMysqlLogInitCtx,
            ALPROTO_MYSQL, JsonMysqlLogger);

    /* do not put in eve-log */
}

#else /* HAVE_LIBJANSSON */

#endif /* HAVE_LIBJANSSON */
