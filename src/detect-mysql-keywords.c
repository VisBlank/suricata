/**
 * \ingroup mysql-layer
 */

/**
 * \file
 * \auth
 * Implement various MySQL keywords:
 *  mysql_login
 *  mysql_command
 *  ...
 */
#include "suricata-common.h"
#include "app-layer-mysql.h"
#include "detect.h"

static int DetectMysqlLoginSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
static int DetectMysqlDisableLoginSetup(DetectEngineCtx *de_ctx, Signature *s, char *str);
void DetectMysqlKeywordsFree(void);

void DetectMysqlLoginRegister(void) {
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].name = "mysql_login";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].desc = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].url = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Match = NULL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].AppLayerMatch = NULL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].alproto = ALPROTO_MYSQL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Setup = DetectMysqlLoginSetup;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Free = NULL;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].RegisterTests = NULL;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].flags |= SIGMATCH_PAYLOAD;
}

void DetectMysqlDisableLoginRegister(void) {
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].name = "mysql_disable_login";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].desc = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].url = "mysql TBD";
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Match = NULL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].AppLayerMatch = NULL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].alproto = ALPROTO_MYSQL; 
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Setup = DetectMysqlDisableLoginSetup;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].Free = NULL;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].RegisterTests = NULL;
    sigmatch_table[DETECT_AL_MYSQL_LOGIN].flags |= SIGMATCH_PAYLOAD;
}

static int DetectMysqlLoginSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    /* FIXME: how about to use DetectEngineContentModifierBufferSetup() */

    /* TODO: we need to parse the @str to */
    s->list = DETECT_SM_LIST_MYSQL_LOGIN_MATCH;
    s->alproto = ALPROTO_MYSQL;
    return 0;
}

static int DetectMysqlDisableLoginSetup(DetectEngineCtx *de_ctx, Signature *s, char *str) {
    /* TODO */
    return 0;
}
