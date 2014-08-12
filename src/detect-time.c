/**
 * \file
 * \auth: tanb
 * various time detect according to iptables rules
 *
 * time detect stolen from iptables($ man iptables):
 *
 * date         (format is `year-month-day')
 * weekdays     (only support 1-7 currently)
 * time         (format is `hour:minute:second', and is 24-hours format)
 * monthdays    (format is 1~31)
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"

typedef struct DetectDate_ {
    int y[2];
    int m[2];
    int d[2];
    time_t start, end;
} DetectDate;

typedef struct DetectWeekdays_ {
    char wd[7];
} DetectWeekdays;

typedef struct DetectMonthdays_ {
    char md[31];
} DetectMonthdays;

typedef struct DetectTime_ {
    short h[2];
    short m[2];
    short s[2];
} DetectTime;

static void DetectDateFree(void *ptr);
static int DetectDateSetup(DetectEngineCtx *ctx, Signature *s, char *str);
static int DetectDateMatch(ThreadVars *t, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m);
static int DetectDateParse(char *str, DetectDate *dss);

static int DetectTimeMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m);
static int DetectTimeSetup(DetectEngineCtx *ctx, Signature *s, char *str);
static void DetectTimeFree(void *ptr);
static int DetectTimeParse(char *str, DetectTime *tss);

static int DetectWeekdaysMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m);
static int DetectWeekdaysSetup(DetectEngineCtx *ctx, Signature *s, char *str);
static void DetectWeekdaysFree(void *ptr);
static int DetectWeekdaysParse(char *str, DetectWeekdays *wd);

static int DetectMonthdaysMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m);
static int DetectMonthdaysSetup(DetectEngineCtx *ctx, Signature *s, char *str);
static void DetectMonthdaysFree(void *ptr);
static int DetectMonthdaysParse(char *str, DetectMonthdays *md);

void DetectTimeRegister(void) {
    sigmatch_table[DETECT_DATE].name = "date";
    sigmatch_table[DETECT_DATE].desc = "match on date of the package been transferred";
    sigmatch_table[DETECT_DATE].url = "";
    sigmatch_table[DETECT_DATE].Match = DetectDateMatch;
    sigmatch_table[DETECT_DATE].Setup = DetectDateSetup;
    sigmatch_table[DETECT_DATE].Free = DetectDateFree;
    sigmatch_table[DETECT_DATE].flags |= SIGMATCH_PAYLOAD;

    sigmatch_table[DETECT_TIME].name = "time";
    sigmatch_table[DETECT_TIME].desc = "match on time of the package been transferred";
    sigmatch_table[DETECT_TIME].url = "";
    sigmatch_table[DETECT_TIME].Match = DetectTimeMatch;
    sigmatch_table[DETECT_TIME].Setup = DetectTimeSetup;
    sigmatch_table[DETECT_TIME].Free = DetectTimeFree;
    sigmatch_table[DETECT_TIME].flags |= SIGMATCH_PAYLOAD;

    sigmatch_table[DETECT_WEEKDAYS].name = "weekdays";
    sigmatch_table[DETECT_WEEKDAYS].desc = "match on weekdays of the package been transferred";
    sigmatch_table[DETECT_WEEKDAYS].url = "";
    sigmatch_table[DETECT_WEEKDAYS].Match = DetectWeekdaysMatch;
    sigmatch_table[DETECT_WEEKDAYS].Setup = DetectWeekdaysSetup;
    sigmatch_table[DETECT_WEEKDAYS].Free = DetectWeekdaysFree;
    sigmatch_table[DETECT_WEEKDAYS].flags |= SIGMATCH_PAYLOAD;

    sigmatch_table[DETECT_MONTHDAYS].name = "monthdays";
    sigmatch_table[DETECT_MONTHDAYS].desc = "match on monthdays of the package been transferred";
    sigmatch_table[DETECT_MONTHDAYS].url = "";
    sigmatch_table[DETECT_MONTHDAYS].Match = DetectMonthdaysMatch;
    sigmatch_table[DETECT_MONTHDAYS].Setup = DetectMonthdaysSetup;
    sigmatch_table[DETECT_MONTHDAYS].Free = DetectMonthdaysFree;
    sigmatch_table[DETECT_MONTHDAYS].flags |= SIGMATCH_PAYLOAD;
}


static int DetectDateSetup(DetectEngineCtx *ctx, Signature *s, char *str) {
    DetectDate *dss = NULL;
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    dss = SCMalloc(sizeof(*dss));
    if (dss == NULL)
        goto error;

    memset(dss, 0, sizeof(*dss));

    if (DetectDateParse(str, dss) == -1)
        goto error;
    sm->ctx = dss;
    sm->type = DETECT_DATE;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;

error:
    if (dss != NULL)
        SCFree(dss);
    if (sm != NULL)
        SigMatchFree(sm);
    return -1;
}

static int DetectTimeSetup(DetectEngineCtx *ctx, Signature *s, char *str) {
    DetectTime *tss = NULL;
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    tss = SCMalloc(sizeof(*tss));
    if (tss == NULL)
        goto error;

    memset(tss, 0, sizeof(*tss));

    if (DetectTimeParse(str, tss) == -1)
        goto error;
    sm->ctx = tss;
    sm->type = DETECT_TIME;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;

error:
    if (tss != NULL)
        SCFree(tss);
    if (sm != NULL)
        SigMatchFree(sm);
    return -1;
}

static int DetectDateMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m) {
    DetectDate *dss = (DetectDate *)m->ctx;
    if (p->ts.tv_sec >= dss->start && p->ts.tv_sec <= dss->end)
        return 1;
    return 0;
}

static int DetectTimeMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m) {
    DetectTime *tss = (DetectTime *)m->ctx;

    struct tm t;
    SCLocalTime(p->ts.tv_sec, &t);
    
    struct tm t1;

    t1.tm_mday = t.tm_mday;
    t1.tm_mon = t.tm_mon;
    t1.tm_year = t.tm_year;

    t1.tm_sec = tss->s[0];
    t1.tm_min = tss->m[0];
    t1.tm_hour = tss->h[0];
    time_t tt1 = mktime(&t1);

    t1.tm_sec = tss->s[1];
    t1.tm_min = tss->m[1];
    t1.tm_hour = tss->h[1];
    time_t tt2 = mktime(&t1);

    if (p->ts.tv_sec >= tt1 && p->ts.tv_sec <= tt2)
        return 1;
    return 0;
}

static int ParseYmd(char *str, int len, int *y, int *m, int *d) {
    int fy = 0, fm = 0;
    char *p = str;
    char *q = p;

    while (len-- && *p) {
        if (*p == '-') {
            if (fy == 0) {
                *y = atoi(q);
                fy = 1;
            } else if (fm == 0) {
                *m = atoi(q);
                if (*m > 12)
                    return -1;

                fm = 1;
                q = p + 1;

                *d = atoi(q);
                if (*d > 31)
                    return -1;
                return 0;
            }
            q = p + 1;
        }
        ++p;
    }
    return -1;
}

static int ParseHms(char *str, int len, short *h, short *m, short *s) {
    int fh = 0, fm = 0;
    char *p = str;
    char *q = p;

    while (len-- && *p) {
        if (*p == ':') {
            if (fh == 0) {
                *h = atoi(q);
                if (*h > 24)
                    return -1;

                fh = 1;
            } else if (fm == 0) {
                *m = atoi(q);
                if (*m > 59)
                    return -1;

                fm = 1;
                q = p + 1;
                *s = atoi(q);
                if (*s > 59)
                    return -1;
                return 0;
            }
            q = p + 1;
        }
        ++p;
    }
    return -1;
}

static int DetectDateParse(char *str, DetectDate *dss) {
    char *p = str, *q = p;

    if (dss == NULL)
        return -1;

    while (p[0] == ' ')
        p++;

    int len = strlen(p);
    if (p[0] == '\"' && p[len - 1] == '\"') {
        p++;
        p[len - 1] = '\0';
        len -= 2;
    }

    q = strchr(p, ',');
    if (q == NULL)
        return -1;

    if (ParseYmd(p, q - p, &dss->y[0], &dss->m[0], &dss->d[0]) == -1)
        goto error;
    if (ParseYmd(q + 1, len - (q - p), &dss->y[1], &dss->m[1], &dss->d[1]) == -1)
        goto error;

    struct tm t;
    memset(&t, 0, sizeof(t));
    t.tm_mday = dss->d[0];
    t.tm_mon = dss->m[0] - 1;
    t.tm_year = dss->y[0] - 1900;
    dss->start = mktime(&t);

    memset(&t, 0, sizeof(t));
    t.tm_mday = dss->d[1];
    t.tm_mon = dss->m[1] - 1;
    t.tm_year = dss->y[1] - 1900;
    dss->end = mktime(&t);

    return 0;
error:
    return -1;
}

static int DetectTimeParse(char *str, DetectTime *tss) {
    char *p = str, *q = p;

    if (tss == NULL)
        return -1;

    while (p[0] == ' ')
        p++;

    int len = strlen(p);
    if (p[0] == '\"' && p[len - 1] == '\"') {
        p++;
        p[len - 1] = '\0';
        len -= 2;
    }

    q = strchr(p, ',');
    if (q == NULL)
        return -1;
    if (ParseHms(p, q - p, &tss->h[0], &tss->m[0], &tss->s[0]))
        goto error;
    if (ParseHms(q + 1, len - (q - p), &tss->h[1], &tss->m[1], &tss->s[1]))
        goto error;

    return 0;
error:
    return -1;
}

static void DetectDateFree(void *ptr) {
    SCFree(ptr);
}

static void DetectTimeFree(void *ptr) {
    SCFree(ptr);
}

static int DetectWeekdaysMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m) {
    DetectWeekdays *wd = (DetectWeekdays *)m->ctx;
    struct tm t;
    SCLocalTime(p->ts.tv_sec, &t);
    if (wd->wd[t.tm_wday - 1])
        return 1;
    return 0;
}

static int DetectWeekdaysSetup(DetectEngineCtx *ctx, Signature *s, char *str) {
    DetectWeekdays *wd = NULL;
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    wd = SCMalloc(sizeof(*wd));
    if (wd == NULL)
        goto error;

    memset(wd, 0, sizeof(*wd));

    if (DetectWeekdaysParse(str, wd) == -1)
        goto error;
    sm->ctx = wd;
    sm->type = DETECT_WEEKDAYS;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;

error:
    if (wd != NULL)
        SCFree(wd);
    if (sm != NULL)
        SigMatchFree(sm);
    return -1;
    return 0;
}

static void DetectWeekdaysFree(void *ptr) {
    SCFree(ptr);
}

static int DetectWeekdaysParse(char *str, DetectWeekdays *wd) {
    char *p = str;

    if (wd == NULL)
        return -1;
    while (p[0] == ' ')
        p++;

    int len = strlen(p);
    if (p[0] == '\"' && p[len - 1] == '\"') {
        p++;
        p[len - 1] = '\0';
        len -= 2;
    }

    while (*p) {
        switch (*p) {
            case '1': wd->wd[0] = 1; break;
            case '2': wd->wd[1] = 1; break;
            case '3': wd->wd[2] = 1; break;
            case '4': wd->wd[3] = 1; break;
            case '5': wd->wd[4] = 1; break;
            case '6': wd->wd[5] = 1; break;
            case '7': wd->wd[6] = 1; break;
            default: break;
        }
        ++p;
    }

    return 0;    
}

static int DetectMonthdaysMatch(ThreadVars *tv, DetectEngineThreadCtx *ctx,
        Packet *p, Signature *s, SigMatch *m) {
    DetectMonthdays *md = (DetectMonthdays *)m->ctx;
    struct tm t;
    SCLocalTime(p->ts.tv_sec, &t);
    if (md->md[t.tm_mday - 1])
        return 1;
    return 0;
}

static int DetectMonthdaysSetup(DetectEngineCtx *ctx, Signature *s, char *str) {
    DetectMonthdays *md = NULL;
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    md = SCMalloc(sizeof(*md));
    if (md == NULL)
        goto error;

    memset(md, 0, sizeof(*md));
    if (DetectMonthdaysParse(str, md) == -1)
        goto error;
    sm->ctx = md;
    sm->type = DETECT_MONTHDAYS;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;

error:
    if (md != NULL)
        SCFree(md);
    if (sm != NULL)
        SigMatchFree(sm);
    return -1;
}

static void DetectMonthdaysFree(void *ptr) {
    SCFree(ptr);
}

static int DetectMonthdaysParse(char *str, DetectMonthdays *md) {
    char *p = str;

    if (md == NULL)
        return -1;
    while (p[0] == ' ')
        p++;

    int len = strlen(p);
    if (p[0] == '\"' && p[len - 1] == '\"') {
        p++;
        p[len - 1] = '\0';
        len -= 2;
    }


    int mday = atoi(p); /* first element */
    if (mday > 0 && mday < 32)
        md->md[mday - 1] = 1;
    else
        return -1;

    while (*p) {
        if (*p == ',') {
            p++;
            mday = atoi(p);
            if (mday > 0 && mday < 32)
                md->md[mday - 1] = 1;
            else
                return -1;
        } else {
            p++;
        }
    }

    return 0;
}
