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

#ifndef __APP_LAYER_DETECT_PROTO__H__
#define __APP_LAYER_DETECT_PROTO__H__

typedef uint16_t (*ProbingParserFPtr)(uint8_t *input, uint32_t input_len,
                                      uint32_t *offset);


/**
 * \brief The first function to be called.  This initializes a global
 *        protocol detection context.
 *
 * \retval 0 On succcess;
 * \retval -1 On failure.
 */
int AlpdSetup(void);

/**
 * \brief Registers a protocol for protocol detection phase.
 *
 *        This is the first function to be called after calling the
 *        setup function, AlpdSetup(), before calling any other
 *        app layer functions, alpd or alp, alike.
 *        With this function you are associating/registering a string
 *        that can be used by users to write rules, i.e.
 *        you register the http protocol for protocol detection using
 *        AlpdRegisterProtocol(ctx, ALPROTO_HTTP, "http"),
 *        following which you can write rules like -
 *        alert http any any -> any any (sid:1;)
 *        which basically matches on the HTTP protocol.
 *
 * \param alproto The protocol.
 * \param alproto_str The string to associate with the above "alproto".
 *                    Please send a static string that won't be destroyed
 *                    post making this call, since this function won't
 *                    create a copy of the received argument.
 *
 * \retval  0 On success;
 *         -1 On failure.
 */
int AlpdRegisterProtocol(AppProto alproto, char *alproto_name);

/**
 * \brief Given a protocol name, checks if proto detection is enabled in
 *        the conf file.
 *
 * \param alproto Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AlpdConfProtoDetectionEnabled(const char *alproto);

/**
 * \brief Inits and returns an app layer protocol detection thread context.

 * \param ctx Pointer to the app layer protocol detection context.
 *
 * \retval Pointer to the thread context, on success;
 *         NULL, on failure.
 */
void *AlpdGetCtxThread(void);

/**
 * \brief Destroys the app layer protocol detection thread context.
 *
 * \param tctx Pointer to the app layer protocol detection thread context.
 */
void AlpdDestroyCtxThread(void *tctx);

/**
 * \brief Registers a case-sensitive pattern for protocol detection.
 */
int AlpdPMRegisterPatternCS(uint16_t ipproto, AppProto alproto,
                            char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);
/**
 * \brief Registers a case-insensitive pattern for protocol detection.
 */
int AlpdPMRegisterPatternCI(uint16_t ipproto, AppProto alproto,
                            char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);


/**
 * \brief Prepares the internal state for protocol detection.
 */
int AlpdPrepareState(void);

/**
 * \brief Returns the app layer protocol given a buffer.
 *
 * \param tctx Pointer to the app layer protocol detection thread context.
 * \param f Pointer to the flow.
 * \param buf The buf to be inspected.
 * \param buflen The length of the above buffer.
 * \param ipproto The ip protocol.
 * \param flags The flags field.
 *
 * \retval The app layer protocol.
 */
AppProto AlpdGetProto(void *tctx,
                      Flow *f,
                      uint8_t *buf, uint32_t buflen,
                      uint8_t ipproto, uint8_t flags);


AppProto AlpdGetProtoByName(char *alproto_name);
char *AlpdGetProtoString(AppProto alproto);




void AlpdPPRegister(uint16_t ipproto,
                    char *portstr,
                    AppProto alproto,
                    uint16_t min_depth, uint16_t max_depth,
                    uint8_t flags,
                    ProbingParserFPtr ProbingParser);
void AlpdPPParseConfPorts(const char *alproto_name,
                          AppProto alproto,
                          uint16_t min_depth, uint16_t max_depth,
                          ProbingParserFPtr ProbingParser);

void AlpdSupportedIpprotos(AppProto alproto, uint8_t *ipprotos);


void AlpdRegisterTests(void);










#endif /* __APP_LAYER_DETECT_PROTO__H__ */
