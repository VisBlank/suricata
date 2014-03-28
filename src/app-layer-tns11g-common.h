#ifndef __APP_LAYER_TNS11G_COMMON_H__
#define __APP_LAYER_TNS11G_COMMON_H__
int TNS11gParseClientRecord(Flow *f,
        void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data);

void TNS11gStateFree(void *ds);
void *TNS11gStateAlloc(void);
#endif
