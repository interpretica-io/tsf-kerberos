/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side Kerberos 5 client
 *
 * A Kerberos 5 client on top of **MIT krb5** (@c krb5.h, @c -lkrb5):
 * get a TGT with a principal and password, get a service ticket for an
 * SPN, and probe whether a principal requires pre-authentication (the
 * AS-REP-roasting exposure). The agent and its RPC server both link
 * this; the RPCs (see krb5_rpc.x.m4) are thin wrappers over these
 * functions.
 *
 * Nothing is spawned (no @c kinit) and nothing of the host's state is
 * touched: credentials live in an in-memory ccache for the life of a
 * call. The realm and KDC come from the principal and the agent's
 * @c krb5.conf / DNS, the same as any krb5 client.
 *
 * Results that are records come back as newline-separated text, one
 * @c "key\\tvalue" line per field, the same shape tsf-upnp uses; the
 * engine side parses them.
 */

#ifndef __TA_KERBEROS_H__
#define __TA_KERBEROS_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get a ticket-granting ticket for @p principal with @p password.
 *
 * @param[in]  principal    Client principal, e.g. @c "user@EXAMPLE.COM".
 * @param[in]  password     Its password.
 * @param[out] ok           @c 1 when a TGT was obtained, @c 0 otherwise.
 * @param[out] info         On success, @c "key\\tvalue" lines: client,
 *                          server, starttime, endtime, renewtill,
 *                          enctype (name) and enctype_id.
 * @param[out] reason       On failure, the krb5 error message.
 *
 * @return Status code (of running the request, not of the auth itself).
 */
extern te_errno ta_krb5_get_tgt(const char *principal, const char *password,
                                int *ok, te_string *info, te_string *reason);

/**
 * Get a service ticket for @p spn, authenticating as @p principal.
 *
 * @param[in]  principal    Client principal.
 * @param[in]  password     Its password.
 * @param[in]  spn          Service principal, e.g. @c "host/h@REALM".
 * @param[out] ok           @c 1 when a service ticket was obtained.
 * @param[out] info         On success, @c "key\\tvalue" lines as above
 *                          for the service ticket.
 * @param[out] reason       On failure, the krb5 error message.
 *
 * @return Status code.
 */
extern te_errno ta_krb5_get_service(const char *principal,
                                    const char *password, const char *spn,
                                    int *ok, te_string *info,
                                    te_string *reason);

/**
 * Does @p principal require Kerberos pre-authentication?
 *
 * Sends an AS-REQ and reads the KDC's answer: a
 * @c KDC_ERR_PREAUTH_REQUIRED means pre-authentication is enforced; any
 * other outcome means the KDC will hand out an AS-REP without it, which
 * is the AS-REP-roasting exposure. Sends no valid password.
 *
 * @param[in]  principal        Client principal to probe.
 * @param[out] preauth_required @c 1 when pre-auth is required (good),
 *                              @c 0 when it is not (roastable).
 * @param[out] reason           The KDC's outcome, for the log.
 *
 * @return Status code.
 */
extern te_errno ta_krb5_preauth_probe(const char *principal,
                                      int *preauth_required,
                                      te_string *reason);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_KERBEROS_H__ */
