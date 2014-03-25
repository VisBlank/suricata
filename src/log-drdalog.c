/**
 * author: tanb
 * date: Mon Mar 24 10:11:15 CST 2014
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
#include "app-layer-drda-common.h"

#define OUTPUT_DRDA_MODULE_NAME "LogDRDALog"
#define OUTPUT_DRDA_DEFAULT_LOG_FILENAME "drda.log"
#define OUTPUT_DRDA_BUFFER_SIZE 65535

typedef struct LogDRDALogThread_ {
	LogFileCtx *ctx;
	uint32_t flags; /* store mode */
	uint32_t log_cnt;
	MemBuffer *buffer;
} LogDRDALogThread;

static TmEcode LogDRDAThreadInit(ThreadVars *tv, void *init_data, void **data);
static TmEcode LogDRDAThreadDeinit(ThreadVars *tv, void *init_data);
static OutputCtx *LogDRDALogInitCtx(ConfNode *conf);
static TmEcode LogDRDALog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);

static void LogDRDADeinitCtx(OutputCtx *ctx);
static TmEcode LogDRDALogIPV4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);
static TmEcode LogDRDALogIPV6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);

static void LogDRDALogExitPrintStats(ThreadVars *tv, void *data);

void TmModuleLogDRDARegister(void) {
	tmm_modules[TMM_LOGDRDALOG].name = OUTPUT_DRDA_MODULE_NAME;
	tmm_modules[TMM_LOGDRDALOG].ThreadInit = LogDRDAThreadInit;
	tmm_modules[TMM_LOGDRDALOG].Func = LogDRDALog;
	tmm_modules[TMM_LOGDRDALOG].ThreadExitPrintStats = LogDRDALogExitPrintStats;
	tmm_modules[TMM_LOGDRDALOG].ThreadDeinit = LogDRDAThreadDeinit;
	tmm_modules[TMM_LOGDRDALOG].RegisterTests = NULL;
	tmm_modules[TMM_LOGDRDALOG].cap_flags = 0;

	OutputRegisterModule(OUTPUT_DRDA_MODULE_NAME, "drda-log", LogDRDALogInitCtx);
	SCLogDebug("registered %s", OUTPUT_DRDA_MODULE_NAME);
}

/* FIXME: duplicated with other db log module, we should avoid this */
static TmEcode LogDRDAThreadInit(ThreadVars *tv, void *init_data, void **data) {
	LogDRDALogThread *lt = SCMalloc(sizeof(LogDRDALogThread));
	if (unlikely(lt == NULL))
		return TM_ECODE_FAILED;

	memset(lt, 0, sizeof(LogDRDALogThread));
	if (init_data == NULL) {
		SCLogDebug("Error getting context for DRDALog.  \"initdata\" argument NULL");
		SCFree(lt);
		return TM_ECODE_FAILED;
	}

	lt->buffer = MemBufferCreateNew(OUTPUT_DRDA_BUFFER_SIZE);
	if (NULL == lt->buffer) {
		SCFree(lt);
		return TM_ECODE_FAILED;
	}

	lt->ctx = ((OutputCtx *) init_data)->data;
	*data = (void *)lt;
	return TM_ECODE_OK;
}

static TmEcode LogDRDAThreadDeinit(ThreadVars *tv, void *data) {
	LogDRDALogThread *lt = (LogDRDALogThread *)data;
	if (lt == NULL)
		return TM_ECODE_OK;

	MemBufferFree(lt->buffer);
	memset(lt, 0, sizeof(LogDRDALogThread));

	SCFree(lt);
	return TM_ECODE_OK;
}

static OutputCtx *LogDRDALogInitCtx(ConfNode *conf) {
	LogFileCtx *file_ctx = LogFileNewCtx();
	if (file_ctx == NULL) {
		SCLogError(SC_ERR_TDS_LOG_GENERIC, "could not create new file_ctx");
		return NULL;
	}

	if (SCConfLogOpenGeneric(conf, file_ctx, OUTPUT_DRDA_DEFAULT_LOG_FILENAME) < 0) {
		LogFileFreeCtx(file_ctx);
		return NULL;
	}

	OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
	if (unlikely(output_ctx == NULL)) {
		return NULL;
	}

	output_ctx->data = file_ctx;
	output_ctx->DeInit = LogDRDADeinitCtx;

	SCLogDebug("TDS log output initialized");

	AppLayerRegisterLogger(ALPROTO_TDS);
	return output_ctx;
}

static TmEcode LogDRDALog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
	SCEnter();

	/* no flow, no TDS state */
	if (p->flow == NULL)
		SCReturnInt(TM_ECODE_OK);

	if (!(PKT_IS_TCP(p))) /* only support TCP on TDS */
		SCReturnInt(TM_ECODE_OK);

	if (PKT_IS_IPV4(p))
		SCReturnInt(LogDRDALogIPV4(tv, p, data, pq, postpq));
	else if (PKT_IS_IPV6(p))
		SCReturnInt(LogDRDALogIPV6(tv, p, data, pq, postpq));

	SCReturnInt(TM_ECODE_OK);
}

static void LogDRDADeinitCtx(OutputCtx *ctx) {
	LogFileFreeCtx(ctx->data);
	SCFree(ctx);
}

static TmEcode LogDRDALogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipproto)  {
	SCEnter();
	DRDAState *s = NULL;
	LogDRDALogThread *lt = (LogDRDALogThread *) data;

	if (p->flow == NULL) /* no data, do not to log anything */
		SCReturnInt(TM_ECODE_OK);

	FLOWLOCK_WRLOCK(p->flow);
	uint16_t proto = AppLayerGetProtoFromPacket(p);
	if (proto != ALPROTO_DRDA)
		goto end;

	/* get state that create duing protocol parsing */
	s = (DRDAState *) AppLayerGetProtoStateFromPacket(p);
	if (NULL == s) {
		SCLogDebug("no DRDA state");
		goto end;
	}

	char timebuf[64];
	char srcip[64], dstip[64];
	Port sp = 0, dp = 0;

	CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
	if (PKT_IS_TOSERVER(p)) { /* do not log to client data */
		switch (ipproto) {
			case AF_INET:
				PrintInet(AF_INET, (void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
				PrintInet(AF_INET, (void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
				break;
			case AF_INET6:
				PrintInet(AF_INET6, (void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
				PrintInet(AF_INET6, (void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
				break;
			default:
				goto end;
		}
	} else
		goto end;
	
end:
	FLOWLOCK_UNLOCK(p->flow);
	SCReturnInt(TM_ECODE_OK);
}

static TmEcode LogDRDALogIPV4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
	return LogDRDALogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

static TmEcode LogDRDALogIPV6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
	return LogDRDALogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

static void LogDRDALogExitPrintStats(ThreadVars *tv, void *data) {
	LogDRDALogThread *lt = (LogDRDALogThread *) data;
	if (NULL == lt)
		return;
	SCLogInfo("DB2 logger logged %" PRIu32 " requests", lt->log_cnt);
}
