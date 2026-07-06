/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Kerberos RPC server library
 *
 * The krb5_* RPCs (see krb5_rpc.x.m4) on top of ta_kerberos.
 * TARPC_FUNC_STATIC() binds an RPC to the function of the same name,
 * so each RPC has a plain C function first and the wrapper after it.
 */

#define TE_LGR_USER     "RPC KRB5"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_kerberos.h"

/* Hand a te_string result over to an RPC string field (never NULL). */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

static te_errno
krb5_get_tgt(const char *principal, const char *password, int *ok,
             char **info, char **reason)
{
    te_string i = TE_STRING_INIT;
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_krb5_get_tgt(principal, password, ok, &i, &r);

    *info = take(&i);
    *reason = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(krb5_get_tgt, {},
{
    int ok = 0;

    MAKE_CALL(out->retval = func(in->principal, in->password, &ok,
                                 &out->info, &out->reason));
    out->ok = ok;
    out->common.errno_changed = false;
})

static te_errno
krb5_get_service(const char *principal, const char *password,
                 const char *spn, int *ok, char **info, char **reason)
{
    te_string i = TE_STRING_INIT;
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_krb5_get_service(principal, password, spn, ok, &i, &r);

    *info = take(&i);
    *reason = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(krb5_get_service, {},
{
    int ok = 0;

    MAKE_CALL(out->retval = func(in->principal, in->password, in->spn, &ok,
                                 &out->info, &out->reason));
    out->ok = ok;
    out->common.errno_changed = false;
})

static te_errno
krb5_preauth_probe(const char *principal, int *preauth_required,
                   char **reason)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_krb5_preauth_probe(principal, preauth_required, &r);

    *reason = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(krb5_preauth_probe, {},
{
    int preauth_required = 0;

    MAKE_CALL(out->retval = func(in->principal, &preauth_required,
                                 &out->reason));
    out->preauth_required = preauth_required;
    out->common.errno_changed = false;
})
