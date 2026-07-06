/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Kerberos TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_kerberos. The RPCs return
 * te_errno; an RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI KRB5 RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_kerberos_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* See description in tapi_kerberos_rpc.h */
te_errno
rpc_krb5_get_tgt(rcf_rpc_server *rpcs, const char *principal,
                 const char *password, int *ok, te_string *info,
                 te_string *reason)
{
    tarpc_krb5_get_tgt_in in;
    tarpc_krb5_get_tgt_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.principal = (char *)(principal != NULL ? principal : "");
    in.password = (char *)(password != NULL ? password : "");

    rcf_rpc_call(rpcs, "krb5_get_tgt", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(krb5_get_tgt, out.retval);
    TAPI_RPC_LOG(rpcs, krb5_get_tgt, "%s", "%r ok=%d",
                 principal != NULL ? principal : "", out.retval, out.ok);

    if (out.retval == 0 && ok != NULL)
        *ok = out.ok;
    take_string(info, out.info);
    take_string(reason, out.reason);
    RETVAL_TE_ERRNO(krb5_get_tgt, out.retval);
}

/* See description in tapi_kerberos_rpc.h */
te_errno
rpc_krb5_get_service(rcf_rpc_server *rpcs, const char *principal,
                     const char *password, const char *spn, int *ok,
                     te_string *info, te_string *reason)
{
    tarpc_krb5_get_service_in in;
    tarpc_krb5_get_service_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.principal = (char *)(principal != NULL ? principal : "");
    in.password = (char *)(password != NULL ? password : "");
    in.spn = (char *)(spn != NULL ? spn : "");

    rcf_rpc_call(rpcs, "krb5_get_service", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(krb5_get_service, out.retval);
    TAPI_RPC_LOG(rpcs, krb5_get_service, "%s -> %s", "%r ok=%d",
                 principal != NULL ? principal : "",
                 spn != NULL ? spn : "", out.retval, out.ok);

    if (out.retval == 0 && ok != NULL)
        *ok = out.ok;
    take_string(info, out.info);
    take_string(reason, out.reason);
    RETVAL_TE_ERRNO(krb5_get_service, out.retval);
}

/* See description in tapi_kerberos_rpc.h */
te_errno
rpc_krb5_preauth_probe(rcf_rpc_server *rpcs, const char *principal,
                       int *preauth_required, te_string *reason)
{
    tarpc_krb5_preauth_probe_in in;
    tarpc_krb5_preauth_probe_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.principal = (char *)(principal != NULL ? principal : "");

    rcf_rpc_call(rpcs, "krb5_preauth_probe", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(krb5_preauth_probe, out.retval);
    TAPI_RPC_LOG(rpcs, krb5_preauth_probe, "%s", "%r preauth=%d",
                 principal != NULL ? principal : "", out.retval,
                 out.preauth_required);

    if (out.retval == 0 && preauth_required != NULL)
        *preauth_required = out.preauth_required;
    take_string(reason, out.reason);
    RETVAL_TE_ERRNO(krb5_preauth_probe, out.retval);
}
