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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER__H__
#define __APP_LAYER__H__

#include "threadvars.h"
#include "decode.h"
#include "flow.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#define APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER \
    (~STREAM_TOSERVER & ~STREAM_TOCLIENT)

/**
 * \brief Setup the app layer.
 *
 *        Includes protocol detection setup and the protocol parser setup.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerSetup(void);

/**
 * \brief Creates a new app layer thread context.
 *
 * \retval Pointer to the newly create thread context, on success;
 *         NULL, on failure.
 */
void *AppLayerGetCtxThread(void);

/**
 * \brief Destroys the context created by AppLayeGetCtxThread().
 *
 * \param tctx Pointer to the thread context to destroy.
 */
void AppLayerDestroyCtxThread(void *tctx);

/**
 * \brief Handles reassembled tcp stream.
 */
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                          Packet *p, Flow *f,
                          TcpSession *ssn, TcpStream *stream,
                          uint8_t *data, uint32_t data_len,
                          uint8_t flags);

/**
 * \brief Attach a stream message to the TCP session for inspection
 *        in the detection engine.
 *
 * \param app_layer_tctx Pointer to the app layer thread context.
 * \param smsg Stream message.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerHandleTCPMsg(StreamMsg *smsg);

/**
 * \brief Handles an udp chunk.
 */
int AppLayerHandleUdp(void *app_tctx, Packet *p, Flow *f);

AppProto AppLayerGetProtoByName(char *alproto_name);
char *AppLayerGetProtoString(AppProto alproto);

void AppLayerUnittestsRegister(void);

#endif
