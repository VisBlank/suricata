/*
 * detect oracle keywords
 * author: tanb
 * date: Fri May 16 09:57:05 CST 2014
 */

#include <libinjection.h>

#include "suricata-common.h"
#include "app-layer-oracle11g-common.h"
#include "detect.h"
#include "detect-parse.h"

typedef struct DetectOracle11gKeywords_ {
    uint8_t *user;
    uint8_t *sid;
} DetectOracle11gKeywords; 

static void KeywordsFree(void *ptr);

static int UserMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm);

static int UserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
static int UserParseArg(const char *key, DetectOracle11gKeywords *kw);

static int SidMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm);

static int SidSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
static int SidParseArg(const char *key, DetectOracle11gKeywords *kw);

void DetectOracleKeywordsRegister(void) {
    sigmatch_table[DETECT_AL_ORACLE11G_USER].name = "oracle11g-user";
    sigmatch_table[DETECT_AL_ORACLE11G_USER].AppLayerMatch = UserMatch;
    sigmatch_table[DETECT_AL_ORACLE11G_USER].alproto = ALPROTO_ORACLE11G;
    sigmatch_table[DETECT_AL_ORACLE11G_USER].Setup = UserSetup;
    sigmatch_table[DETECT_AL_ORACLE11G_USER].Free = KeywordsFree;
    sigmatch_table[DETECT_AL_ORACLE11G_USER].flags |= SIGMATCH_PAYLOAD;

    sigmatch_table[DETECT_AL_ORACLE11G_SID].name = "oracle11g-sid";
    sigmatch_table[DETECT_AL_ORACLE11G_SID].AppLayerMatch = SidMatch;
    sigmatch_table[DETECT_AL_ORACLE11G_SID].alproto = ALPROTO_ORACLE11G;
    sigmatch_table[DETECT_AL_ORACLE11G_SID].Setup = SidSetup;
    sigmatch_table[DETECT_AL_ORACLE11G_SID].Free = KeywordsFree;
    sigmatch_table[DETECT_AL_ORACLE11G_SID].flags |= SIGMATCH_PAYLOAD;
    
    /* test to import libinjection into suricata */
    const char *inj_version = libinjection_version();
    printf("libinjection version: %s\n", inj_version);
}

static int UserMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {

    (void) det_ctx;
    (void) f;
    (void) flags;
    (void) sig;

    Oracle11gState *s = alstate;
    if (!s)
        return 0;

    if (!s->conn_data)
        return 0;

    DetectOracle11gKeywords *kw = (DetectOracle11gKeywords *)sm->ctx;
    if (strcmp((const char *)kw->user, (const char *)s->conn_data->user) == 0) {
        s->cur_tx->action= sig->action;
        return 1;
    } else {
        return 0;
    }
}

static int UserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SigMatch *sm = SigMatchAlloc();
    if (!sm)
        goto error;

    sm->type = DETECT_AL_ORACLE11G_USER;
    DetectOracle11gKeywords *kw = SCCalloc(sizeof(*kw), 1);
    if (!kw)
        goto error;
    if (UserParseArg(str, kw) == -1)
        goto error;

    sm->ctx = kw;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    return 0;

error:
    if (sm)
        SigMatchFree(sm);
    if (kw)
        KeywordsFree(kw);
    return -1;
}

static int UserParseArg(const char *key, DetectOracle11gKeywords *kw) {
    uint8_t *str = NULL;
    if (key[0] == '\"' && key[strlen(key) - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (!str)
            return -1;
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (!str)
            return -1;
    }

    kw->user = str;
    return 0;
}

static void KeywordsFree(void *ptr) {
    DetectOracle11gKeywords *kw = ptr;
    if (!kw)
        return;

    if (kw->user)
        SCFree(kw->user);
    if (kw->sid)
        SCFree(kw->sid);

    SCFree(kw);
}

static int SidMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {
    
    (void) det_ctx;
    (void) f;
    (void) flags;
    (void) sig;

    Oracle11gState *s = alstate;
    if (!s)
        return 0;

    DetectOracle11gKeywords *kw = (DetectOracle11gKeywords *)sm->ctx;
    if (strcmp((const char *)kw->sid, (const char *)s->conn_data->sid) == 0) {
        s->cur_tx->action = sig->action;
        return 1;
    } else {
        return 0;
    }
}

static int SidSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SigMatch *sm = SigMatchAlloc();
    if (!sm)
        goto error;

    sm->type = DETECT_AL_ORACLE11G_SID;
    DetectOracle11gKeywords *kw = SCCalloc(sizeof(*kw), 1);
    if (!kw)
        goto error;
    if (SidParseArg(str, kw) == -1)
        goto error;

    sm->ctx = kw;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    return 0;

error:
    if (sm)
        SigMatchFree(sm);
    if (kw)
        KeywordsFree(kw);
    return -1;
}

static int SidParseArg(const char *key, DetectOracle11gKeywords *kw) {
    uint8_t *str = NULL;
    if (key[0] == '\"' && key[strlen(key) - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (!str)
            return -1;
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (!str)
            return -1;
    }

    kw->sid = str;
    return 0;
}
