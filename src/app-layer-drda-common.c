/**
 * \file: app-layer-drda-common.c
 * \author: tanb <tanb@titansec.com.cn>
 * \date: Mon Feb 10 15:22:09 CST 2014
 */

#include "app-layer-drda-common.h"
#include "drda-code-point.c"

#define DRDA_DDM_LEN 10

static char ebcdic_map[256] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
'.' , '<', '(', '+', '|', '&',
0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 
'!', '$', '*', ')', ';', 0x95 '-', '/',
0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
'|', ',', '%', '_', '>', '?',
0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
'`', ':', '#', '@', '\'', '=', '"',
0x80,
'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
0x8A ,0x8B ,0x8C ,0x8D ,0x8E ,0x8F ,0x90,
'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
'~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
0xAA ,0xAB ,0xAC ,0xAD ,0xAE ,0xAF ,0xB0 ,0xB1 ,0xB2 ,0xB3,
0xB4 ,0xB5 ,0xB6 ,0xB7 ,0xB8 ,0xB9 ,0xBA ,0xBB ,0xBC ,0xBD,
0xBE ,0xBF,
'{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
0xCA ,0xCB ,0xCC ,0xCD ,0xCE ,0xCF,
'}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
0xDA ,0xDB ,0xDC ,0xDD ,0xDE ,0xDF,
'\\',
0xE1,
'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
0xEA ,0xEB ,0xEC ,0xED ,0xEE ,0xEF,
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '|',
0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
};

struct DRDAState_ {
    
};

static int DRDAParseParameter(struct DRDAState_ *s, uint8_t *in, uint32_t len) {
    uint16_t param_cp = 0,
             offset = 0,
             param_len = 0;

    /* there may be multiple parameters in @in */
    while (offset <= len) {
        if (ByteExtractUint16(&param_len, BYTE_LITTLE_ENDIAN, 2, in + offset) == -1)
            SCReturnInt(-1);

        if (ByteExtractUint16(&param_cp, BYTE_LITTLE_ENDIAN, 2, in + offset + 2) == -1)
            SCReturnInt(-1);
        
        uint8_t *data = NULL;
        uint16_t data_sz = 0;
        switch (param_cp) {
            /* TODO: we should transfer EBCDIC to ASCII for some @param_cp type,
             * if not labeled, default is ASCII encoded */
            case DRDA_CP_DATA:
                if (param_len == 0) { /* need more verify... */
                    /* as type DRDA_CP_DATA, the length field is zero,
                     * means copy the remind bytes as the data.
                     *
                     * the data seems like encaped with * a byte
                     * prefix(`%` or `$` or others) and a 0xff suffix
                     * 
                     * type of DRDA_CP_DATA is in ASCII format, not EBCDIC
                     */
                    data_sz = (len - offset) - 2 * sizeof(uint16_t) - 2 + 1;
                    data = SCCalloc(data_sz);
                    memcpy(data, in + offset + 4, data_sz);

                    /* TODO: should we attach the data to @s? and how? */
                    /* data is the last part of the DDM(verify that), just return */
                    return
                }
                break;

                /* note: here the DATADA_CP_SRVXXX not only apply to DB2 server, but
                 * also apply to DB2 client, they share the same  @param_cp value,
                 * these data used to exchange attributes between client and server
                 */
            case DRDA_CP_SRVNAM:    /* EBCDIC encoded: server app name, not DB2 Server name */
            case DRDA_CP_SRVRLSLV:  /* EBCDIC encoded: server product release level */
            case DRDA_CP_SRVCLSNM:  /* EBCDIC encoded: server class name  */
            case DRDA_CP_EXTNAM:    /* EBCDIC encoded: external name */
            case DRDA_CP_RDBNAM:    /* rational database name */
            case DRDA_CP_SECTKN:    /* security token */
            case DRDA_CP_USRID:     /* user name at the target DB2 server system */
            case DRDA_CP_CRRTKN:    /* correlation token */
            case DRDA_CP_PRDID:
            default:
                /* TODO: we have other parameters to parse */
                break;
        }
        offset += param_len;
    }

    return 0;
}

int DRDAParseClientRecord(Flow *f,
        void *alstate,
        AppLayerParserState *alps, uint8_t *in,
        uint32_t in_len, void *local_data,
        AppLayerParserResult *res) {

    int offset = 0;
    struct drdaState_ *s = alstate;

    /* there may be multiple DRDA commands in @in */
    for (;;) {
        uint16_t res = 0;
        uint16_t ddm_cp = 0, param_cp = 0;
        int len = ByteExtractUint16(&res, BYTE_LITTLE_ENDIAN, 2, in + offset);
        if (len < DRDA_DDM_LEN) {
           SCLogError("Invalid length detected (%u): should be at least 10 bytes long", len); 
           break;
        }

        /* last 2 byte of DDM is code point */
        ByteExtractUint16(&ddm_cp, BYTE_LITTLE_ENDIAN, 2,
                in + offset + DRDA_DDM_LEN - sizeof(uint16_t));

        switch (ddm_cp) {
            /* skip these command */
            case DRDA_CP_EXCSAT:
            case DRDA_CP_EXCSQLSET:
                break;
            case DRDA_CP_SQLSTT: /* comes the SQL statement */
                if (DRDAParseParameter(s, in + offset + DRDA_DDM_LEN, len - DRDA_DDM_LEN) == -1)
                    SCLogError("DRDAParseParameter error on DRDA_CP_SQLSTT");
                break;
            default: break;
        }

        offset += len; 
        continue;
    }

    return 0;
} 
