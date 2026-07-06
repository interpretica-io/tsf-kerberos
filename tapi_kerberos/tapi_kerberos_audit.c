/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a Kerberos realm is worth as a security posture
 *
 * Drives tapi_kerberos and classifies the result into tsf-cybersec
 * findings: AS-REP roasting (pre-auth not required) and weak session
 * enctypes.
 */

#define TE_LGR_USER     "TAPI KRB5 AUDIT"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "logger_api.h"

#include "tapi_kerberos.h"
#include "tapi_kerberos_audit.h"

/* See description in tapi_kerberos_audit.h */
te_errno
tapi_krb5_audit(rcf_rpc_server *rpcs, const tapi_krb5_audit_policy *policy,
                tapi_cybersec_report *report)
{
    bool assessed = false;

    if (policy == NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "krb5.not-assessed", "-", "no Kerberos policy given");
        return 0;
    }

    if (policy->preauth_principal != NULL &&
        policy->preauth_principal[0] != '\0')
    {
        bool required = true;
        te_errno rc = tapi_krb5_preauth_required(rpcs,
                          policy->preauth_principal, &required);

        if (rc == 0)
        {
            assessed = true;
            if (!required)
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                    "krb5.preauth-not-required", policy->preauth_principal,
                    "the KDC returns an AS-REP without pre-authentication "
                    "(AS-REP roasting)");
            }
        }
    }

    if (policy->principal != NULL && policy->principal[0] != '\0' &&
        policy->password != NULL)
    {
        tapi_krb5_ticket ticket;
        bool ok = false;
        te_errno rc = tapi_krb5_get_tgt(rpcs, policy->principal,
                                        policy->password, &ok, &ticket);

        if (rc == 0 && ok)
        {
            assessed = true;
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                "krb5.tgt-obtained", policy->principal,
                "TGT obtained, session enctype %s (%d)",
                ticket.enctype != NULL ? ticket.enctype : "?",
                ticket.enctype_id);
            if (tapi_krb5_enctype_is_weak(ticket.enctype_id))
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                    "krb5.weak-enctype", policy->principal,
                    "the KDC issued a weak session key (%s)",
                    ticket.enctype != NULL ? ticket.enctype : "?");
            }
            tapi_krb5_ticket_free(&ticket);
        }
    }

    if (!assessed)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "krb5.not-assessed", "-",
            "no principal could be assessed (none configured or reachable)");
    }

    return 0;
}
