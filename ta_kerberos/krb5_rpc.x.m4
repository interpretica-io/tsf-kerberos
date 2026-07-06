/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for Kerberos 5 client operations
 *
 * The RPCs of rpcs_kerberos, a thin layer over ta_kerberos, which runs
 * an MIT krb5 client in the RPC server process. Add this file to the
 * rpcxdr definitions of the engine platform and of the agent platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_kerberos/krb5_rpc.x.m4])
 *
 * No handle survives between calls: each request authenticates afresh
 * into an in-memory ccache. Record results come back as newline-
 * separated "key \t value" text, the engine side parses them.
 */

/* krb5_get_tgt(): get a TGT with principal+password. */
struct tarpc_krb5_get_tgt_in {
    struct tarpc_in_arg common;

    string          principal<>;
    string          password<>;
};

struct tarpc_krb5_get_tgt_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       ok;
    string          info<>;
    string          reason<>;
};

/* krb5_get_service(): get a service ticket for an SPN. */
struct tarpc_krb5_get_service_in {
    struct tarpc_in_arg common;

    string          principal<>;
    string          password<>;
    string          spn<>;
};

struct tarpc_krb5_get_service_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       ok;
    string          info<>;
    string          reason<>;
};

/* krb5_preauth_probe(): does the principal require pre-authentication? */
struct tarpc_krb5_preauth_probe_in {
    struct tarpc_in_arg common;

    string          principal<>;
};

struct tarpc_krb5_preauth_probe_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       preauth_required;
    string          reason<>;
};

program krb5
{
    version ver0
    {
        RPC_DEF(krb5_get_tgt)
        RPC_DEF(krb5_get_service)
        RPC_DEF(krb5_preauth_probe)
    } = 1;
} = 42;
