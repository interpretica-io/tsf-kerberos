/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Kerberos TAPI: RPC client wrappers
 *
 * Client wrappers of the krb5_* RPCs, see krb5_rpc.x.m4. Tests use
 * tapi_kerberos.h; these are the calls behind it, one per RPC.
 */

#ifndef __TAPI_KERBEROS_RPC_H__
#define __TAPI_KERBEROS_RPC_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Get a TGT; @p info is the "key\\tvalue" record, @p ok the result. */
extern te_errno rpc_krb5_get_tgt(rcf_rpc_server *rpcs, const char *principal,
                                 const char *password, int *ok,
                                 te_string *info, te_string *reason);

/** Get a service ticket for @p spn. */
extern te_errno rpc_krb5_get_service(rcf_rpc_server *rpcs,
                                     const char *principal,
                                     const char *password, const char *spn,
                                     int *ok, te_string *info,
                                     te_string *reason);

/** Probe pre-authentication; @p preauth_required is the verdict. */
extern te_errno rpc_krb5_preauth_probe(rcf_rpc_server *rpcs,
                                       const char *principal,
                                       int *preauth_required,
                                       te_string *reason);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_KERBEROS_RPC_H__ */
