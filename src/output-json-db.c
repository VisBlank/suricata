/*
 * author: coanor <coanor@gmail.com>
 * date: Wed Mar 26 16:07:44 CST 2014
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

#include "output.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"

#include "app-layer-mysql-common.h"
#include "app-layer-tns-common.h"
#include "app-layer-tds-common.h"
#include "app-layer-drda-common.h"

typedef struct DBJsonLogCtx_ {
	LogFileCtx *ctx;
	uint32_t flags;
} DBJsonLogCtx;

typedef struct DBJsonLogThread_ {
	DBJsonLogCtx *ctx;
	uint32_t cnt;
	MemBuffer *buf;
} DBJsonLogThread;

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define DB_JSON_SIZE 65536
static TmEcode ThreadInit(ThreadVars *t, void *init_data, void **data) {
	DBJsonLogThread *jlt = SCCalloc(sizeof(*jlt), 1);
	if (unlikely(jlt == NULL))
		return TM_ECODE_FAILED;

	if (!init_data) {
		SCLogDebug("Error getting context for DNSLog.  \"initdata\" argument NULL");
		SCFree(jlt);
		return TM_ECODE_FAILED;
	}

	jlt->buf = MemBufferCreateNew(DB_JSON_SIZE);
	if (!jlt->buf) {
		SCFree(jlt);
		return TM_ECODE_FAILED;
	}

	jlt->ctx = ((OutputCtx *)init_data)->data;
	*data = (void *)jlt;
	return TM_ECODE_OK;
}

static TmEcode ThreadDeinit(ThreadVars *t, void *data) {
	DBJsonLogThread *jlt = (DBJsonLogThread *)data;
	if (jlt == NULL) {
		return TM_ECODE_OK;
	}

	MemBufferFree(jlt->buf);
	/* clear memory */
	memset(jlt, 0, sizeof(DBJsonLogThread));

	SCFree(jlt);
	return TM_ECODE_OK;
}

static void DeinitCtx(OutputCtx *output_ctx) {
	DBJsonLogCtx *ctx = (DBJsonLogCtx *)output_ctx->data;
	LogFileFreeCtx(ctx->ctx);
	SCFree(ctx);
	SCFree(output_ctx);
}

static OutputCtx *InitCtx(ConfNode *conf, AppProto proto, const char *dft_name) {
	LogFileCtx *ctx = LogFileNewCtx();
	if (ctx == NULL) {
		SCLogError(SC_ERR_JONS_LOG_GENERIC, "couldn't create new file_ctx");
		return NULL;
	}
	
	if (SCConfLogOpenGeneric(conf, ctx, dft_name) < 0) {
		LogFileFreeCtx(ctx);
		return NULL;
	}

	DBJsonLogCtx *jctx = SCCalloc(sizeof(*jctx) , 1);
	if (unlikely(jctx == NULL)) {
		LogFileFreeCtx(ctx);
		return NULL;
	}

	jctx->ctx = ctx;
	OutputCtx *octx = SCCalloc(1, sizeof(*octx));
	if (unlikely(octx == NULL)) {
		LogFileFreeCtx(ctx);
		SCFree(jctx);
		return NULL;
	}

	octx->data = jctx;
	octx->DeInit = DeinitCtx;
	SCLogDebug("log output initialized");

	AppLayerParserRegisterLogger(IPPROTO_TCP, proto);
	return octx;
}

static OutputCtx *MysqlInitCtx(ConfNode *conf) {
	return InitCtx(conf, ALPROTO_MYSQL, "mysql.json");
}

static OutputCtx *TNSInitCtx(ConfNode *conf) {
	return InitCtx(conf, ALPROTO_TNS, "oracle-tns.json");
}

static OutputCtx *TDSInitCtx(ConfNode *conf) {
	return InitCtx(conf, ALPROTO_TDS, "mssql-tds.json");
}

static OutputCtx *DRDAInitCtx(ConfNode *conf) {
	return InitCtx(conf, ALPROTO_DRDA, "db2-drda.json");
}

static void DBLogAlState(void *alstate, AppProto proto,
		const Packet *p, json_t *js, const char *name) {
    if ((PKT_IS_TOCLIENT(p))) {
		return;
	}

    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    char srcip[46], dstip[46];

	json_t *dbjs = json_object();
	if (dbjs == NULL)
		return;

	if (PKT_IS_IPV4(p)) {
		PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
		PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
	} else {
		PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
		PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
	}

#if 0
	char *dbtype = AlstateGetDBType(alstate, proto);
	char *username = AlstateGetUsername(alstate, proto);
	char *dbname = AlstateGetDBname(alstate, proto);
	char *dbopr = AlstateGetDBOpr(alstate, proto);
	char *action = AlstateGetAction(alstate, proto);
	char *meta = AlstateGetMetaInfo(alstate, proto);

	if (dbtype != NULL) {
		json_object_set_new(dbjs, "time", timebuf);
	}

	if (username != NULL) {
		json_object_set_new(dbjs, "user", username);
	}

	if (dbname != NULL) {
		json_object_set_new(dbjs, "db_name", dbname);
	}

	if (dbopr != NULL) {
		json_object_set_new(dbjs, "db_operation", dbopr);
	}

	if (action != NULL) {
		json_object_set_new(dbjs, "action", action);
	}

	if (meta != NULL) {
		json_object_set_new(dbjs, "meta_info", meta);
	}
#endif

	json_object_set_new(js, name, dbjs);
}

static int Logger(ThreadVars *t, void *thread_data, const Packet *p,
		Flow *f, void *alstate, void *txptr, uint64_t tx_id) {
	SCEnter();
	char *name = NULL;

	DBJsonLogThread *jlt = (DBJsonLogThread *)thread_data;

	switch (f->alproto) {
		case ALPROTO_MYSQL:
			name = "mysql";
		case ALPROTO_TNS:
			name = "oracle-tns";
		case ALPROTO_TDS:
			name = "mssql-tds";
		case ALPROTO_DRDA:
			name = "db2-drda";
		default:
			SCReturnInt(-1);
	}

	json_t *js = CreateJSONHeader((Packet *)p, 1, name);
	MemBufferReset(jlt->buf);

	/* TODO */
	DBLogAlState(alstate, f->alproto, p, js, name);

	OutputJSONBuffer(js, jlt->ctx->ctx, jlt->buf);
	json_object_del(js, name);
	json_object_clear(js);
	json_decref(js);
	SCReturnInt(TM_ECODE_OK);
}

void TmModuleJsonMysqlLogRegister (void) {
	static char module_name[] = "JsonMysqlLog";
	tmm_modules[TMM_JSON_MYSQL_LOG].name = module_name;
	tmm_modules[TMM_JSON_MYSQL_LOG].ThreadInit = ThreadInit;
	tmm_modules[TMM_JSON_MYSQL_LOG].ThreadDeinit = ThreadDeinit;
	tmm_modules[TMM_JSON_MYSQL_LOG].RegisterTests = NULL;
	tmm_modules[TMM_JSON_MYSQL_LOG].cap_flags = 0;
	tmm_modules[TMM_JSON_MYSQL_LOG].flags = TM_FLAG_LOGAPI_TM;

	OutputRegisterTxModule(module_name, "mysql-json-log", MysqlInitCtx, ALPROTO_MYSQL, Logger);
}

void TmModuleJsonTNSLogRegister (void) {
	static char module_name[] = "JsonTNSLog";
	tmm_modules[TMM_JSON_TNS_LOG].name = module_name;
	tmm_modules[TMM_JSON_TNS_LOG].ThreadInit = ThreadInit;
	tmm_modules[TMM_JSON_TNS_LOG].ThreadDeinit = ThreadDeinit;
	tmm_modules[TMM_JSON_TNS_LOG].RegisterTests = NULL;
	tmm_modules[TMM_JSON_TNS_LOG].cap_flags = 0;
	tmm_modules[TMM_JSON_TNS_LOG].flags = TM_FLAG_LOGAPI_TM;

	OutputRegisterTxModule(module_name, "tns-json-log", TNSInitCtx, ALPROTO_TNS, Logger);
}

void TmModuleJsonTDSLogRegister (void) {
	static char module_name[] = "JsonTDSLog";
	tmm_modules[TMM_JSON_TDS_LOG].name = module_name;
	tmm_modules[TMM_JSON_TDS_LOG].ThreadInit = ThreadInit;
	tmm_modules[TMM_JSON_TDS_LOG].ThreadDeinit = ThreadDeinit;
	tmm_modules[TMM_JSON_TDS_LOG].RegisterTests = NULL;
	tmm_modules[TMM_JSON_TDS_LOG].cap_flags = 0;
	tmm_modules[TMM_JSON_TDS_LOG].flags = TM_FLAG_LOGAPI_TM;

	OutputRegisterTxModule(module_name, "tns-json-log", TDSInitCtx, ALPROTO_TDS, Logger);
}

void TmModuleJsonDRDALogRegister (void) {
	static char module_name[] = "JsonDRDALog";
	tmm_modules[TMM_JSON_DRDA_LOG].name = module_name;
	tmm_modules[TMM_JSON_DRDA_LOG].ThreadInit = ThreadInit;
	tmm_modules[TMM_JSON_DRDA_LOG].ThreadDeinit = ThreadDeinit;
	tmm_modules[TMM_JSON_DRDA_LOG].RegisterTests = NULL;
	tmm_modules[TMM_JSON_DRDA_LOG].cap_flags = 0;
	tmm_modules[TMM_JSON_DRDA_LOG].flags = TM_FLAG_LOGAPI_TM;

	OutputRegisterTxModule(module_name, "dadr-json-log", DRDAInitCtx, ALPROTO_DRDA, Logger);
}

#else /* no json support */

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data) {
	SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
	return TM_ECODE_FAILED;
}

void TmModuleJsonMysqlLogRegisger(void) {
	tmm_modules[TMM_JSON_MYSQL_LOG].name = "JsonMysqlLog";
	tmm_modules[TMM_JSON_MYSQL_LOG].ThreadInit = OutputJsonThreadInit;
}

void TmModuleJsonTNSLogRegisger(void) {
	tmm_modules[TMM_JSON_TNS_LOG].name = "JsonTNSLog";
	tmm_modules[TMM_JSON_TNS_LOG].ThreadInit = OutputJsonThreadInit;
}

void TmModuleJsonTDSLogRegisger(void) {
	tmm_modules[TMM_JSON_TDS_LOG].name = "JsonTDSLog";
	tmm_modules[TMM_JSON_TDS_LOG].ThreadInit = OutputJsonThreadInit; 
}

void TmModuleJsonDRDALogRegisger(void) {
	tmm_modules[TMM_JSON_DRDA_LOG].name = "JsonDRDALog";
	tmm_modules[TMM_JSON_DRDA_LOG].ThreadInit = OutputJsonThreadInit;
}
#endif
