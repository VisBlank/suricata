/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_PARSER__H__
#define __APP_LAYER_PARSER__H__

#include "decode-events.h"
#include "util-file.h"

#define APP_LAYER_PARSER_EOF            0x01
#define APP_LAYER_PARSER_NO_INSPECTION  0x02
#define APP_LAYER_PARSER_NO_REASSEMBLY  0x04

int AlpSetup(void);

/**
 * \brief Gets a new app layer protocol's parser thread context.
 *
 * \retval Non-NULL pointer on success.
 *         NULL pointer on failure.
 */
void *AlpGetCtxThread(void);

/**
 * \brief Destroys the app layer parser thread context obtained
 *        using AlpGetCtxThread().
 *
 * \param tctx Pointer to the thread context to be destroyed.
 */
void AlpDestroyCtxThread(void *tctx);

/**
 * \brief Given a protocol name, checks if the parser is enabled in
 *        the conf file.
 *
 * \param alproto_name Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AlpConfParserEnabled(const char *alproto_name);

/***** Parser related registration *****/

/**
 * \brief Register app layer parser for the protocol.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AlpRegisterParser(uint16_t ip_proto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    void *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage));
void AlpRegisterParserAcceptableDataDirection(uint16_t ipproto,
                                              AppProto alproto,
                                              uint8_t direction);
void AlpRegisterStateFuncs(uint16_t ipproto, AppProto alproto,
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *));
void AlpRegisterLocalStorageFunc(uint16_t ipproto, AppProto proto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *));
void AlpRegisterGetFilesFunc(uint16_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t));
void AlpRegisterGetEventsFunc(uint16_t ipproto, AppProto proto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t));
void AlpRegisterHasEventsFunc(uint16_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *));
void AlpRegisterLogger(uint16_t ipproto, AppProto alproto);
void AlpRegisterTruncateFunc(uint16_t ipproto, AppProto alproto,
                             void (*Truncate)(void *, uint8_t));
void AlpRegisterGetStateProgressFunc(uint16_t ipproto, AppProto alproto,
    int (*StateGetStateProgress)(void *alstate, uint8_t direction));
void AlpRegisterTxFreeFunc(uint16_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t));
void AlpRegisterGetTxCnt(uint16_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate));
void AlpRegisterGetTx(uint16_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id));
void AlpRegisterGetStateProgressCompletionStatus(uint16_t ipproto,
                                                 uint16_t alproto,
    int (*StateGetStateProgressCompletionStatus)(uint8_t direction));
void AlpRegisterGetEventInfo(uint16_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type));

/***** Get and transaction functions *****/

void *AlpGetProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto);
void AlpDestroyProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto,
                                          void *local_data);


uint64_t AlpGetTransactionLogId(void *pstate);
void AlpSetTransactionLogId(void *pstate);
uint64_t AlpGetTransactionInspectId(void *pstate, uint8_t direction);
void AlpSetTransactionInspectId(void *pstate,
                                uint16_t ipproto, AppProto alproto, void *alstate,
                                uint8_t direction);
AppLayerDecoderEvents *AlpGetDecoderEvents(void *pstate);
void AlpSetDecoderEvents(void *pstate, AppLayerDecoderEvents *devents);
AppLayerDecoderEvents *AlpGetEventsByTx(uint16_t ipproto, AppProto alproto, void *alstate,
                                        uint64_t tx_id);
uint16_t AlpGetStateVersion(void *pstate);
FileContainer *AlpGetFiles(uint16_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction);
int AlpGetStateProgress(uint16_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction);
uint64_t AlpGetTxCnt(uint16_t ipproto, AppProto alproto, void *alstate);
void *AlpGetTx(uint16_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id);
int AlpGetStateProgressCompletionStatus(uint16_t ipproto, AppProto alproto,
                                        uint8_t direction);
int AlpGetEventInfo(uint16_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type);

uint64_t AlpGetTransactionActive(uint16_t ipproto, AppProto alproto, void *pstate, uint8_t direction);

uint8_t AlpGetFirstDataDir(uint16_t ipproto, uint16_t alproto);

/***** General *****/

int AlpParseL7Data(void *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, uint8_t *input, uint32_t input_len);
void AlpSetEOF(void *pstate);
int AlpHasDecoderEvents(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate,
                        uint8_t flags);
int AlpProtocolIsTxEventAware(uint16_t ipproto, AppProto alproto);
int AlpProtocolSupportsTxs(uint16_t ipproto, AppProto alproto);
void AlpTriggerRawStreamReassembly(Flow *f);

/***** Cleanup *****/

void AlpCleanupParserState(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate);

void AlpRegisterProtocolParsers(void);

/***** Unittests *****/

#ifdef UNITTESTS
void AlpRegisterUnittests(uint16_t alproto, void (*RegisterUnittests)(void));
void AlpBackupParserTable(void);
void AlpRestoreParserTable(void);
#endif

void AlpParserStateSetFlag(void *pstate, uint8_t flag);
int AlpParserStateIssetFlag(void *pstate, uint8_t flag);

void AlpStreamTruncated(uint16_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction);



void *AlpAllocAlpParserState(void);
void AlpDeAllocAlpParserState(void *pstate);



#ifdef DEBUG
void AlpPrintDetailsParserState(void *pstate);
#endif







#endif
