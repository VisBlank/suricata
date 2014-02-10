/**
 * \file
 * \author: tanb <tanb@titansec.com.cn>
 * \date: Mon Feb 10 15:06:58 CST 2014
 * common implement for DRDA protocol used in IBM DB2 C/S communication
 */
#ifndef __APP_LAYER_DRDA_COMMON_H__
#define __APP_LAYER_DRDA_COMMON_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

typedef struct DRDAClient_ {
} DRDAClient;

int DRDAParseClientRecord(Flow *f,
        void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data,
        AppLayerParserResult *out);

int DRDAParseServerRecord(Flow *f,
        void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data,
        AppLayerParserResult *out);
void DRDAStateFree(void *ds);
void *DRDAStateAlloc(void);
#endif
