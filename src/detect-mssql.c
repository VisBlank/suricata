/*
 * author: tanb
 * date: Wed Jun 18 12:58:25 CST 2014
 */

#include "suricata-common.h"
#include "app-layer-mssql-common.h"
#include "detect.h"
#include "detect-parse.h"

typedef struct DetectMSSqlKeywords_ {
    uint8_t *user;
    uint8_t *db_name;
} DetectMSSqlKeywords;

static void MSSqlKeywordsFree(void *ptr);
static int MSSqlUserMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *sig, SigMatch *sm);

static int MSSqlUserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
static int MSSqlUserParseArg(const char *key, DetectMSSqlKeywords *kw);

static int MSSqlDbMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm);

static int MSSqlDbSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
static int MSSqlDbParseArg(const char *key, DetectMSSqlKeywords *kw);

void DetectMSSqlKeywordsRegister(void) {
    sigmatch_table[DETECT_AL_MSSQL_USER].name = "mssql-user";
    sigmatch_table[DETECT_AL_MSSQL_USER].AppLayerMatch = MSSqlUserMatch;
    sigmatch_table[DETECT_AL_MSSQL_USER].alproto = ALPROTO_MSSQL;
    sigmatch_table[DETECT_AL_MSSQL_USER].Setup = MSSqlUserSetup;
    sigmatch_table[DETECT_AL_MSSQL_USER].Free = MSSqlKeywordsFree;
    sigmatch_table[DETECT_AL_MSSQL_USER].flags |= SIGMATCH_PAYLOAD;

    sigmatch_table[DETECT_AL_MSSQL_DB].name = "mssql-db";
    sigmatch_table[DETECT_AL_MSSQL_DB].AppLayerMatch = MSSqlDbMatch;
    sigmatch_table[DETECT_AL_MSSQL_DB].alproto = ALPROTO_MSSQL;
    sigmatch_table[DETECT_AL_MSSQL_DB].Setup = MSSqlDbSetup;
    sigmatch_table[DETECT_AL_MSSQL_DB].Free = MSSqlKeywordsFree;
    sigmatch_table[DETECT_AL_MSSQL_DB].flags |= SIGMATCH_PAYLOAD;
}

static int MSSqlUserMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {
    (void) det_ctx;
    (void) f;
    (void) flags;

    TDSState *s = alstate;
    if (!s)
        return 0;

    DetectMSSqlKeywords *kw = sm->ctx;
    if (strcmp((const char *)kw->user, (const char *)s->cli.user_name) == 0) {
        s->cur_tx->action = sig->action;
        return 1;
    } else {
        return 0;
    }
}

static int MSSqlUserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SigMatch *sm = SigMatchAlloc();
    DetectMSSqlKeywords *kw = NULL;
    if (!sm)
        goto error;

    sm->type = DETECT_AL_MSSQL_USER;
    kw = SCCalloc(sizeof(*kw), 1);
    if (!kw)
        goto error;
    if (MSSqlUserParseArg(str, kw) == -1)
        goto error;

    sm->ctx = kw;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    return 0;

error:
    if (sm)
        SigMatchFree(sm);
    if (kw)
        MSSqlKeywordsFree(kw);
    return -1;
}

static int MSSqlUserParseArg(const char *key, DetectMSSqlKeywords *kw) {
    uint8_t *str = NULL;
    int len = strlen(key);
    if (key[0] == '\"' && key[len - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (!str)
            return -1;
        str[len - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (!str)
            return -1;
    }

    kw->user = str;
    return 0;
}

static void MSSqlKeywordsFree(void *ptr) {
    DetectMSSqlKeywords *kw = ptr;
    if (!kw)
        return;

    if (kw->user)
        SCFree(kw->user);
    if (kw->db_name)
        SCFree(kw->db_name);
    SCFree(kw);
}

static int MSSqlDbMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {
    
    (void) det_ctx;
    (void) f;
    (void) flags;

    TDSState *s = alstate;
    if (!s)
        return 0;

    DetectMSSqlKeywords *kw = sm->ctx;
    if (!s->cli.db_name) /* db_name optional */
        return 0;

    if (strcmp((const char *)kw->db_name, (const char *)s->cli.db_name) == 0) {
        s->cur_tx->action = sig->action;
        return 1;
    } else {
        return 0;
    }
}

static int MSSqlDbSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SigMatch *sm = SigMatchAlloc();
    DetectMSSqlKeywords *kw = NULL;
    if (!sm)
        goto error;

    sm->type = DETECT_AL_MSSQL_DB;
    kw = SCCalloc(sizeof(*kw), 1);
    if (!kw)
        goto error;
    if (MSSqlDbParseArg(str, kw) == -1)
        goto error;

    sm->ctx = kw;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    return 0;

error:
    if (sm)
        SigMatchFree(sm);
    if (kw)
        MSSqlKeywordsFree(kw);

    return -1;
}

static int MSSqlDbParseArg(const char *key, DetectMSSqlKeywords *kw) {
    uint8_t *str = NULL;
    int len = strlen(key);
    if (key[0] == '\"' && key[len - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (!str)
            return -1;
        str[len - 2] = '\0';
    } else {
        str = (uint8_t *)strdup(key);
        if (!str)
            return -1;
    }

    kw->db_name = str;
    return 0;
}
