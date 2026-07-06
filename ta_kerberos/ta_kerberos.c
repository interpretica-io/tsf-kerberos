/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side Kerberos 5 client over MIT krb5
 *
 * Written against the MIT krb5 1.20 C API. The library is linked and
 * called in-process; no kinit is run. Credentials are kept in an
 * in-memory ccache (@c MEMORY:) that lives only for the call, so the
 * host's default ccache and keytab are never touched.
 */

#define TE_LGR_USER     "TA KRB5"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include <krb5.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_kerberos.h"

/** A krb5 error turned into a TE status, with the message in @p reason. */
static te_errno
krb5_fail(krb5_context ctx, krb5_error_code code, const char *what,
          te_string *reason)
{
    const char *msg = ctx != NULL ? krb5_get_error_message(ctx, code) : NULL;

    ERROR("%s: krb5 error %ld (%s)", what, (long)code,
          msg != NULL ? msg : "?");
    if (reason != NULL)
        te_string_append(reason, "%s", msg != NULL ? msg : "krb5 error");
    if (msg != NULL)
        krb5_free_error_message(ctx, msg);

    return TE_RC(TE_TA_UNIX, TE_EFAIL);
}

/** Append the fields of a krb5_creds to @p info as "key\tvalue" lines. */
static void
krb5_report_creds(krb5_context ctx, krb5_creds *creds, te_string *info)
{
    char *client = NULL;
    char *server = NULL;
    char ename[128] = "";

    if (krb5_unparse_name(ctx, creds->client, &client) == 0)
    {
        te_string_append(info, "client\t%s\n", client);
        krb5_free_unparsed_name(ctx, client);
    }
    if (krb5_unparse_name(ctx, creds->server, &server) == 0)
    {
        te_string_append(info, "server\t%s\n", server);
        krb5_free_unparsed_name(ctx, server);
    }
    te_string_append(info, "starttime\t%ld\n", (long)creds->times.starttime);
    te_string_append(info, "endtime\t%ld\n", (long)creds->times.endtime);
    te_string_append(info, "renewtill\t%ld\n", (long)creds->times.renew_till);

    if (krb5_enctype_to_name(creds->keyblock.enctype, false,
                             ename, sizeof(ename)) == 0)
        te_string_append(info, "enctype\t%s\n", ename);
    te_string_append(info, "enctype_id\t%d\n", (int)creds->keyblock.enctype);
}

/* See description in ta_kerberos.h */
te_errno
ta_krb5_get_tgt(const char *principal, const char *password, int *ok,
                te_string *info, te_string *reason)
{
    krb5_context ctx = NULL;
    krb5_principal princ = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_creds creds;
    krb5_error_code code;
    te_errno rc = 0;

    *ok = 0;
    memset(&creds, 0, sizeof(creds));

    code = krb5_init_context(&ctx);
    if (code != 0)
        return krb5_fail(NULL, code, "krb5_init_context", reason);

    code = krb5_parse_name(ctx, principal, &princ);
    if (code != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_parse_name", reason);
        goto out;
    }

    code = krb5_get_init_creds_opt_alloc(ctx, &opt);
    if (code != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_get_init_creds_opt_alloc", reason);
        goto out;
    }

    code = krb5_get_init_creds_password(ctx, &creds, princ,
                                        (char *)password, NULL, NULL, 0,
                                        NULL, opt);
    if (code != 0)
    {
        /* Not a transport failure - the auth was refused; report it. */
        if (reason != NULL)
        {
            const char *msg = krb5_get_error_message(ctx, code);

            te_string_append(reason, "%s", msg != NULL ? msg : "denied");
            if (msg != NULL)
                krb5_free_error_message(ctx, msg);
        }
        goto out;
    }

    *ok = 1;
    krb5_report_creds(ctx, &creds, info);
    krb5_free_cred_contents(ctx, &creds);

out:
    if (opt != NULL)
        krb5_get_init_creds_opt_free(ctx, opt);
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);

    return rc;
}

/* See description in ta_kerberos.h */
te_errno
ta_krb5_get_service(const char *principal, const char *password,
                    const char *spn, int *ok, te_string *info,
                    te_string *reason)
{
    krb5_context ctx = NULL;
    krb5_principal princ = NULL;
    krb5_principal sprinc = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_ccache cc = NULL;
    krb5_creds tgt;
    krb5_creds in_creds;
    krb5_creds *out_creds = NULL;
    krb5_error_code code;
    te_errno rc = 0;

    *ok = 0;
    memset(&tgt, 0, sizeof(tgt));
    memset(&in_creds, 0, sizeof(in_creds));

    code = krb5_init_context(&ctx);
    if (code != 0)
        return krb5_fail(NULL, code, "krb5_init_context", reason);

    if ((code = krb5_parse_name(ctx, principal, &princ)) != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_parse_name", reason);
        goto out;
    }
    if ((code = krb5_parse_name(ctx, spn, &sprinc)) != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_parse_name(spn)", reason);
        goto out;
    }
    if ((code = krb5_get_init_creds_opt_alloc(ctx, &opt)) != 0)
    {
        rc = krb5_fail(ctx, code, "opt_alloc", reason);
        goto out;
    }

    code = krb5_get_init_creds_password(ctx, &tgt, princ, (char *)password,
                                        NULL, NULL, 0, NULL, opt);
    if (code != 0)
    {
        if (reason != NULL)
        {
            const char *msg = krb5_get_error_message(ctx, code);

            te_string_append(reason, "%s", msg != NULL ? msg : "denied");
            if (msg != NULL)
                krb5_free_error_message(ctx, msg);
        }
        goto out;
    }

    /* A ccache the TGT lives in, so krb5_get_credentials can use it. */
    if ((code = krb5_cc_new_unique(ctx, "MEMORY", NULL, &cc)) != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_cc_new_unique", reason);
        krb5_free_cred_contents(ctx, &tgt);
        goto out;
    }
    krb5_cc_initialize(ctx, cc, princ);
    krb5_cc_store_cred(ctx, cc, &tgt);

    in_creds.client = princ;
    in_creds.server = sprinc;
    code = krb5_get_credentials(ctx, 0, cc, &in_creds, &out_creds);
    krb5_free_cred_contents(ctx, &tgt);
    if (code != 0)
    {
        if (reason != NULL)
        {
            const char *msg = krb5_get_error_message(ctx, code);

            te_string_append(reason, "%s", msg != NULL ? msg : "no ticket");
            if (msg != NULL)
                krb5_free_error_message(ctx, msg);
        }
        goto out;
    }

    *ok = 1;
    krb5_report_creds(ctx, out_creds, info);
    krb5_free_creds(ctx, out_creds);

out:
    if (cc != NULL)
        krb5_cc_destroy(ctx, cc);
    if (opt != NULL)
        krb5_get_init_creds_opt_free(ctx, opt);
    if (sprinc != NULL)
        krb5_free_principal(ctx, sprinc);
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);

    return rc;
}

/* See description in ta_kerberos.h */
te_errno
ta_krb5_preauth_probe(const char *principal, int *preauth_required,
                      te_string *reason)
{
    krb5_context ctx = NULL;
    krb5_principal princ = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_creds creds;
    krb5_error_code code;
    const char *msg;
    te_errno rc = 0;

    *preauth_required = 0;
    memset(&creds, 0, sizeof(creds));

    code = krb5_init_context(&ctx);
    if (code != 0)
        return krb5_fail(NULL, code, "krb5_init_context", reason);

    if ((code = krb5_parse_name(ctx, principal, &princ)) != 0)
    {
        rc = krb5_fail(ctx, code, "krb5_parse_name", reason);
        goto out;
    }
    if ((code = krb5_get_init_creds_opt_alloc(ctx, &opt)) != 0)
    {
        rc = krb5_fail(ctx, code, "opt_alloc", reason);
        goto out;
    }

    /*
     * AS-REQ with no usable password. The KDC's answer tells us about
     * pre-auth: KRB5KDC_ERR_PREAUTH_REQUIRED means it is enforced; a
     * reply that gets as far as decrypting an AS-REP (wrong password:
     * KRB5KDC_ERR_PREAUTH_FAILED / KRB5_PREAUTH_FAILED / success) means
     * an AS-REP is handed out without pre-auth - the roasting exposure.
     */
    code = krb5_get_init_creds_password(ctx, &creds, princ, "", NULL, NULL,
                                        0, NULL, opt);
    msg = krb5_get_error_message(ctx, code);

    if (code == KRB5KDC_ERR_PREAUTH_REQUIRED)
    {
        *preauth_required = 1;
        if (reason != NULL)
            te_string_append(reason, "pre-authentication required");
    }
    else if (code == 0)
    {
        /* An empty password actually worked - AS-REP without pre-auth. */
        *preauth_required = 0;
        if (reason != NULL)
            te_string_append(reason, "AS-REP returned (no pre-auth)");
        krb5_free_cred_contents(ctx, &creds);
    }
    else
    {
        /*
         * Reached the AS-REP exchange (e.g. decrypt/preauth failed on
         * the wrong password) => the KDC did not demand pre-auth first.
         */
        *preauth_required = 0;
        if (reason != NULL)
            te_string_append(reason, "%s", msg != NULL ? msg : "no pre-auth");
    }
    if (msg != NULL)
        krb5_free_error_message(ctx, msg);

out:
    if (opt != NULL)
        krb5_get_init_creds_opt_free(ctx, opt);
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);

    return rc;
}
