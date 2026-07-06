/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Kerberos 5 from a test
 *
 * The engine-side layer over the krb5_* RPCs: it asks the agent to
 * authenticate and parses the newline/tab ticket record into a
 * #tapi_krb5_ticket.
 */

#define TE_LGR_USER     "TAPI KRB5"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_kerberos.h"
#include "tapi_kerberos_rpc.h"

/** Pull the value of @p key from "key\tvalue\n" record text (heap/NULL). */
static char *
krb5_field(const char *text, const char *key)
{
    size_t klen = strlen(key);
    const char *line = text;

    while (line != NULL && *line != '\0')
    {
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);

        if (len > klen && strncmp(line, key, klen) == 0 && line[klen] == '\t')
            return TE_STRNDUP(line + klen + 1, len - klen - 1);
        line = nl != NULL ? nl + 1 : NULL;
    }
    return NULL;
}

/** Parse the ticket record text into @p ticket. */
static void
krb5_parse_ticket(const char *text, tapi_krb5_ticket *ticket)
{
    char *v;

    memset(ticket, 0, sizeof(*ticket));
    ticket->client = krb5_field(text, "client");
    ticket->server = krb5_field(text, "server");
    ticket->enctype = krb5_field(text, "enctype");
    if ((v = krb5_field(text, "starttime")) != NULL)
    { ticket->starttime = strtol(v, NULL, 10); free(v); }
    if ((v = krb5_field(text, "endtime")) != NULL)
    { ticket->endtime = strtol(v, NULL, 10); free(v); }
    if ((v = krb5_field(text, "renewtill")) != NULL)
    { ticket->renewtill = strtol(v, NULL, 10); free(v); }
    if ((v = krb5_field(text, "enctype_id")) != NULL)
    { ticket->enctype_id = (int)strtol(v, NULL, 10); free(v); }
}

/* See description in tapi_kerberos.h */
te_errno
tapi_krb5_get_tgt(rcf_rpc_server *rpcs, const char *principal,
                  const char *password, bool *ok, tapi_krb5_ticket *ticket)
{
    te_string info = TE_STRING_INIT;
    te_string reason = TE_STRING_INIT;
    int got = 0;
    te_errno rc;

    rc = rpc_krb5_get_tgt(rpcs, principal, password, &got, &info, &reason);
    if (ok != NULL)
        *ok = (got != 0);
    if (rc == 0 && got == 0)
        RING("krb5: no TGT for %s: %s", principal, te_string_value(&reason));
    if (rc == 0 && got != 0 && ticket != NULL)
        krb5_parse_ticket(te_string_value(&info), ticket);

    te_string_free(&info);
    te_string_free(&reason);
    return rc;
}

/* See description in tapi_kerberos.h */
te_errno
tapi_krb5_get_service(rcf_rpc_server *rpcs, const char *principal,
                      const char *password, const char *spn, bool *ok,
                      tapi_krb5_ticket *ticket)
{
    te_string info = TE_STRING_INIT;
    te_string reason = TE_STRING_INIT;
    int got = 0;
    te_errno rc;

    rc = rpc_krb5_get_service(rpcs, principal, password, spn, &got, &info,
                              &reason);
    if (ok != NULL)
        *ok = (got != 0);
    if (rc == 0 && got == 0)
        RING("krb5: no service ticket %s: %s", spn,
             te_string_value(&reason));
    if (rc == 0 && got != 0 && ticket != NULL)
        krb5_parse_ticket(te_string_value(&info), ticket);

    te_string_free(&info);
    te_string_free(&reason);
    return rc;
}

/* See description in tapi_kerberos.h */
te_errno
tapi_krb5_preauth_required(rcf_rpc_server *rpcs, const char *principal,
                           bool *required)
{
    te_string reason = TE_STRING_INIT;
    int req = 0;
    te_errno rc;

    rc = rpc_krb5_preauth_probe(rpcs, principal, &req, &reason);
    if (rc == 0 && required != NULL)
        *required = (req != 0);
    if (rc == 0)
        RING("krb5: %s pre-auth %s (%s)", principal,
             req ? "required" : "NOT required", te_string_value(&reason));

    te_string_free(&reason);
    return rc;
}

/* See description in tapi_kerberos.h */
bool
tapi_krb5_enctype_is_weak(int enctype_id)
{
    switch (enctype_id)
    {
        case 1:   /* des-cbc-crc */
        case 2:   /* des-cbc-md4 */
        case 3:   /* des-cbc-md5 */
        case 23:  /* arcfour-hmac (RC4) */
        case 24:  /* arcfour-hmac-exp */
            return true;
        default:
            return false;
    }
}

/* See description in tapi_kerberos.h */
void
tapi_krb5_ticket_free(tapi_krb5_ticket *ticket)
{
    free(ticket->client);
    free(ticket->server);
    free(ticket->enctype);
    memset(ticket, 0, sizeof(*ticket));
}
