# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side Kerberos 5 client
# over MIT krb5 (krb5.h, -lkrb5 -lgssapi_krb5 -lk5crypto -lcom_err). The
# agent and its RPC server both link it.

headers += files(
    'ta_kerberos.h',
)

sources += files(
    'ta_kerberos.c',
)

te_libs += [
    'logger_core',
    'tools',
]

cc = meson.get_compiler('c')

krb5_dep = dependency('krb5', required: false)
if not krb5_dep.found()
    krb5_dep = cc.find_library('krb5', has_headers: 'krb5.h')
endif
gssapi_dep = dependency('krb5-gssapi', required: false)
if not gssapi_dep.found()
    gssapi_dep = cc.find_library('gssapi_krb5', required: false)
endif

deps += [ krb5_dep ]
if gssapi_dep.found()
    deps += [ gssapi_dep ]
endif