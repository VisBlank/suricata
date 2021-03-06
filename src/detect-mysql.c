/**
 * \file
 * \auth
 * Implement various MySQL keywords:
 *  mysql-user
 *  mysql-command
 *  mysql-db
 *  ...
 */
#include "suricata-common.h"
#include "app-layer-mysql-common.h"
#include "detect.h"
#include "detect-parse.h"

typedef struct DetectMysqlUser_ {
    uint8_t *username;
} DetectMysqlUser;

typedef struct DetectMysqlDb_ {
    uint8_t *db_name;
} DetectMysqlDb;

static int DetectMysqlUserALMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *s, SigMatch *sm);
static int DetectMysqlUserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
int DetectMysqlUserParseArg(const char *key, DetectMysqlUser *mu);
static void DetectMysqlUserFree(void *ptr);

static int DetectMysqlDbALMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *s, SigMatch *sm);
static int DetectMysqlDbSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
int DetectMysqlDbParseArg(const char *key, DetectMysqlDb *md);

static void DetectMysqlDbFree(void *ptr);

void DetectMysqlKeywordsRegister(void) {
    sigmatch_table[DETECT_AL_MYSQL_USER].name = "mysql-user";
    sigmatch_table[DETECT_AL_MYSQL_USER].desc = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_USER].url = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_USER].Match = NULL;
    sigmatch_table[DETECT_AL_MYSQL_USER].AppLayerMatch = DetectMysqlUserALMatch;
    sigmatch_table[DETECT_AL_MYSQL_USER].alproto = ALPROTO_MYSQL;
    sigmatch_table[DETECT_AL_MYSQL_USER].Setup = DetectMysqlUserSetup;
    sigmatch_table[DETECT_AL_MYSQL_USER].Free = DetectMysqlUserFree;
    sigmatch_table[DETECT_AL_MYSQL_USER].RegisterTests = NULL;
    sigmatch_table[DETECT_AL_MYSQL_USER].flags |= SIGMATCH_PAYLOAD;
    
    sigmatch_table[DETECT_AL_MYSQL_DB].name = "mysql-database";
    sigmatch_table[DETECT_AL_MYSQL_DB].desc = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_DB].url = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_DB].Match = NULL; 
    sigmatch_table[DETECT_AL_MYSQL_DB].AppLayerMatch = DetectMysqlDbALMatch; 
    sigmatch_table[DETECT_AL_MYSQL_DB].alproto = ALPROTO_MYSQL; 
    sigmatch_table[DETECT_AL_MYSQL_DB].Setup = DetectMysqlDbSetup;
    sigmatch_table[DETECT_AL_MYSQL_DB].Free = DetectMysqlDbFree;
    sigmatch_table[DETECT_AL_MYSQL_DB].RegisterTests = NULL;
    sigmatch_table[DETECT_AL_MYSQL_DB].flags |= SIGMATCH_PAYLOAD;
}

static int DetectMysqlUserSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SCEnter();

    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MYSQL_USER;
    DetectMysqlUser *mu = SCMalloc(sizeof(DetectMysqlUser));
    if (mu == NULL)
        goto error;
    memset(mu, 0, sizeof(*mu));
    if (DetectMysqlUserParseArg(str, mu) == -1)
        goto error;

    sm->ctx = mu;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (sm != NULL)
        SigMatchFree(sm);
    if (mu != NULL) {
        DetectMysqlUserFree((void *)mu);
    }
    SCReturnInt(-1);
}

static void DetectMysqlUserFree(void *ptr) {
    DetectMysqlUser *mu = (DetectMysqlUser *)ptr;
    if (mu != NULL) {
        if (mu->username != NULL)
            SCFree(mu->username);
        
        SCFree(mu);
    }
}

int DetectMysqlUserParseArg(const char *key, DetectMysqlUser *mu) {
    uint8_t *str;
    if (key[0] == '\"' && key[strlen(key) - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (unlikely(str == NULL))
            goto error;
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (unlikely(str == NULL))
            goto error;
    }

    mu->username = str;
    return 0;
error:
    if (str != NULL)
        SCFree(str);
    return -1;
}

static int DetectMysqlUserALMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {
    SCEnter();

    (void) det_ctx;
    (void) f;
    (void) flags;
    (void) sig;

    MysqlState *s = (MysqlState *)alstate;
    if (s == NULL) {
        SCLogDebug("no mysql state, no match");
        SCReturnInt(0);
    }

    DetectMysqlUser *mu = (DetectMysqlUser *)sm->ctx;
    
    if (strcmp((const char *)mu->username, (const char *)s->cli.username) == 0) {
        s->cur_tx->action = sig->action; /* the action will take on this transaction */
        return 1;
    } else {
        return 0;
    }
}

static int DetectMysqlDbALMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, Signature *sig, SigMatch *sm) {

    (void) det_ctx;
    (void) f;
    (void) flags;
    (void) sig;

    MysqlState *s = (MysqlState *)alstate;
    if (s == NULL)
        SCReturnInt(0);

    DetectMysqlDb *md = (DetectMysqlDb *)sm->ctx;

    /* on login mysql, db name is optional, succesive `use some-db` 
     * command is parsed in dedicated SQL Parser */
    if ((const char *)s->cli.db_name) { 
        if (strcmp((const char *)md->db_name, (const char *)s->cli.db_name) == 0) {
            s->cur_tx->action = sig->action;
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}

static int DetectMysqlDbSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    SCEnter();

    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MYSQL_DB;
    DetectMysqlDb *md = SCMalloc(sizeof(DetectMysqlDb));
    if (md == NULL)
        goto error;
    memset(md, 0, sizeof(*md));
    if (DetectMysqlDbParseArg(str, md) == -1)
        goto error;

    sm->ctx = md;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (sm != NULL)
        SigMatchFree(sm);
    if (md != NULL) {
        DetectMysqlUserFree((void *)md);
    }
    SCReturnInt(-1);
    return 0;
}

int DetectMysqlDbParseArg(const char *key, DetectMysqlDb *md) {
    uint8_t *str;
    if (key[0] == '\"' && key[strlen(key) - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (unlikely(str == NULL))
            goto error;
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (unlikely(str == NULL))
            goto error;
    }

    md->db_name = str;
    return 0;
error:
    if (str != NULL)
        SCFree(str);
    return -1;
    return 0;
}

static void DetectMysqlDbFree(void *ptr) {
    DetectMysqlDb *md = (DetectMysqlDb *)ptr;
    if (md != NULL) {
        if (md->db_name != NULL)
            SCFree(md->db_name);
        
        SCFree(md);
    }
}

#ifdef UNITTESTS
/* TODO add unit tests */
#endif
