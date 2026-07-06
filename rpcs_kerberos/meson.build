# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): the krb5_* RPCs for the RPC
# server of an agent. List it in the libraries of the ta_rpcprovider
# application together with ta_kerberos, and add
# ta_kerberos/krb5_rpc.x.m4 to the rpcxdr definitions of both platforms.

sources += files(
    'rpcs_kerberos.c',
)

te_libs += [
    'rpcserver',
    'ta_kerberos',
]
