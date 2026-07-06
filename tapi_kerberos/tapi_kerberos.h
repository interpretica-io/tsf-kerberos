/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Kerberos 5 from a test
 *
 * @defgroup tapi_kerberos Kerberos 5 (tapi_kerberos)
 * @{
 *
 * Authenticating to a Kerberos 5 realm from a Test Agent with MIT krb5:
 * get a ticket-granting ticket, get a service ticket for an SPN, and
 * ask whether a principal requires pre-authentication. The krb5 library
 * runs in the agent's RPC server; the realm and KDC come from the
 * principal and the agent's krb5.conf/DNS.
 *
 * - @ref tapi_kerberos - the client calls;
 * - @ref tapi_kerberos_audit (tapi_kerberos_audit.h) - a realm read as a
 *   security posture through tsf-cybersec.
 *
 * Pairs with tsf-smb for Active Directory assessments.
 */

#ifndef __TAPI_KERBEROS_H__
#define __TAPI_KERBEROS_H__

#include "te_defs.h"
#include "te_errno.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A Kerberos ticket as obtained from the KDC. */
typedef struct tapi_krb5_ticket {
    /** Client principal, e.g. @c "user@EXAMPLE.COM". */
    char *client;
    /** Server/service principal (the TGS or the SPN). */
    char *server;
    /** Start time (Unix seconds). */
    long starttime;
    /** Expiry (Unix seconds). */
    long endtime;
    /** Renew-till (Unix seconds), or @c 0. */
    long renewtill;
    /** Session-key enctype name (e.g. @c "aes256-cts-hmac-sha1-96"). */
    char *enctype;
    /** Session-key enctype numeric id. */
    int enctype_id;
} tapi_krb5_ticket;

/**
 * Get a ticket-granting ticket.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  principal    Client principal, e.g. @c "user@REALM".
 * @param[in]  password     Its password.
 * @param[out] ok           @c true when a TGT was obtained.
 * @param[out] ticket       The ticket on success, or @c NULL to ignore;
 *                          release with tapi_krb5_ticket_free().
 *
 * @return Status code (of the exchange, not of the auth verdict).
 */
extern te_errno tapi_krb5_get_tgt(rcf_rpc_server *rpcs, const char *principal,
                                  const char *password, bool *ok,
                                  tapi_krb5_ticket *ticket);

/**
 * Get a service ticket for @p spn.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  principal    Client principal.
 * @param[in]  password     Its password.
 * @param[in]  spn          Service principal, e.g. @c "host/h@REALM".
 * @param[out] ok           @c true when a service ticket was obtained.
 * @param[out] ticket       The ticket, or @c NULL; free with
 *                          tapi_krb5_ticket_free().
 *
 * @return Status code.
 */
extern te_errno tapi_krb5_get_service(rcf_rpc_server *rpcs,
                                      const char *principal,
                                      const char *password, const char *spn,
                                      bool *ok, tapi_krb5_ticket *ticket);

/**
 * Does @p principal require pre-authentication?
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  principal    Client principal to probe.
 * @param[out] required     @c true when pre-auth is required (good),
 *                          @c false when the KDC yields an AS-REP
 *                          without it (AS-REP-roastable).
 *
 * @return Status code.
 */
extern te_errno tapi_krb5_preauth_required(rcf_rpc_server *rpcs,
                                           const char *principal,
                                           bool *required);

/**
 * Is an enctype id a weak one (single-DES or RC4/arcfour)?
 *
 * @param enctype_id    krb5 enctype number.
 *
 * @return @c true for DES-CBC-* and RC4-HMAC(-EXP).
 */
extern bool tapi_krb5_enctype_is_weak(int enctype_id);

/**
 * Release a ticket.
 *
 * @param ticket    Ticket.
 */
extern void tapi_krb5_ticket_free(tapi_krb5_ticket *ticket);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_KERBEROS_H__ */

/**@} <!-- END tapi_kerberos --> */
