/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a Kerberos realm is worth as a security posture
 *
 * @defgroup tapi_kerberos_audit Kerberos security posture
 * @ingroup tapi_kerberos
 * @{
 *
 * A Kerberos realm read as a security posture and reported through
 * tsf-cybersec: whether a principal hands out an AS-REP without
 * pre-authentication (AS-REP roasting), and whether the KDC issues a
 * weak (single-DES or RC4) session key.
 *
 * It authenticates to a real KDC/AD and, for the pre-auth probe, sends
 * an AS-REQ for a named principal - so it is for an **authorized**
 * assessment of a realm you own or are engaged to test.
 *
 * | Finding | Severity | Raised when |
 * |---|---|---|
 * | @c krb5.preauth-not-required | high | the KDC returns an AS-REP for the principal without pre-auth |
 * | @c krb5.weak-enctype | medium | the TGT's session key is single-DES or RC4 |
 * | @c krb5.tgt-obtained | info | a TGT was obtained for the principal |
 * | @c krb5.not-assessed | info | nothing to probe (no principal configured) |
 */

#ifndef __TAPI_KERBEROS_AUDIT_H__
#define __TAPI_KERBEROS_AUDIT_H__

#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What a realm's Kerberos is expected to be. */
typedef struct tapi_krb5_audit_policy {
    /**
     * A principal whose pre-authentication to probe (AS-REP roasting),
     * or @c NULL to skip that check. No password is sent.
     */
    const char *preauth_principal;
    /**
     * A principal + password to obtain a TGT and inspect its enctype,
     * or @c NULL to skip. The password is the suite's to supply.
     */
    const char *principal;
    /** Password for @a principal. */
    const char *password;
} tapi_krb5_audit_policy;

/**
 * Read a realm's Kerberos posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  policy   What to probe (principals/password).
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_krb5_audit(rcf_rpc_server *rpcs,
                                const tapi_krb5_audit_policy *policy,
                                tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_KERBEROS_AUDIT_H__ */

/**@} <!-- END tapi_kerberos_audit --> */
