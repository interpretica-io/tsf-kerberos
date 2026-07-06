# tsf-kerberos

Kerberos 5 from a Test Agent, packaged as an external Test Environment
(TE) repository (consumed with the `TE_EXT_REPO` builder directive). It
drives Kerberos over a low-level C library — **MIT krb5, no `kinit`,
nothing spawned** — for both authentication and a security posture.

Three libraries:

- `ta_kerberos` — agent side. An MIT krb5 client (`krb5.h`, `-lkrb5
  -lgssapi_krb5`): get a TGT with a principal and password, get a
  service ticket for an SPN, and probe whether a principal requires
  pre-authentication. Credentials live in an in-memory (`MEMORY:`)
  ccache for the life of a call — the host's default ccache and keytab
  are never touched. The agent and its RPC server both link it.
- `rpcs_kerberos` — the `krb5_*` RPCs for the agent's RPC server, thin
  wrappers over `ta_kerberos`.
- `tapi_kerberos` — engine side. `tapi_kerberos.h` gives a test
  `tapi_krb5_get_tgt()`, `tapi_krb5_get_service()` and
  `tapi_krb5_preauth_required()` with parsed ticket details;
  `tapi_kerberos_audit.h` reads a realm as a security posture through
  tsf-cybersec; `tapi_kerberos_rpc.h` is the one-per-RPC layer beneath.

TE has no Kerberos client of its own. Pairs with tsf-smb for Active
Directory assessments.

## Authorized use only

The posture authenticates to a real KDC/AD and sends an AS-REQ for a
named principal. It is for an **authorized** assessment — a realm you
own or are engaged to test.

## Security posture

`tapi_krb5_audit()` reports through tsf-cybersec's finding model:

| Finding | Severity | Raised when |
|---|---|---|
| `krb5.preauth-not-required` | high | the KDC returns an AS-REP for a principal without pre-authentication (AS-REP roasting) |
| `krb5.weak-enctype` | medium | the TGT's session key is single-DES or RC4/arcfour |
| `krb5.tgt-obtained` | info | a TGT was obtained |
| `krb5.not-assessed` | info | nothing could be probed |

A finding's subject is the principal/realm (stable between runs).

## Agent host requirements

- **MIT krb5** with development headers — Debian/Ubuntu:
  `apt install libkrb5-dev` (gives `krb5.h`, `-lkrb5 -lgssapi_krb5
  -lk5crypto -lcom_err`, 1.20+). **MIT, not Heimdal** — the API here is
  MIT's.
- A reachable KDC for the realm, configured the usual way
  (`/etc/krb5.conf` or DNS SRV records).

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_kerberos
    url: https://github.com/interpretica-io/tsf-kerberos.git
    ref: <tag>
    libs:
      - ta_kerberos
      - rpcs_kerberos
      - tapi_kerberos
```

In `builder.conf`, bind `tapi_kerberos` to the engine, list
`ta_kerberos` and `rpcs_kerberos` among the RPC server's libraries, and
add the RPC definitions to both platforms:

```
TE_EXT_REPO_USE([tsf_kerberos], [], [ta_kerberos rpcs_kerberos tapi_kerberos])

TE_LIB_PARMS([rpcxdr], [${TE_HOST}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_kerberos/krb5_rpc.x.m4])
```

`tapi_kerberos_audit` reports through tsf-cybersec, so that repository
(and tsf-kernel, tsf-devtool beneath it) must be built too. The RPC
program number is **42** (20–41 are taken by the other tsf agent RPCs).

## What was verified, and what was not

**Built and run natively on lasirena** (Ubuntu 24.04, MIT krb5 1.20.1):
the module compiles and links against libkrb5, and the suite
`tsf-kerberos-ts` runs — it skips cleanly when no realm/principal is
configured. A live run against a real KDC needs a realm, a principal
and (for the enctype check) a password, supplied through the suite's
environment.

The pre-auth probe is a **heuristic**: it reads the KDC's answer to an
AS-REQ sent with no usable password. `KDC_ERR_PREAUTH_REQUIRED` is read
as "pre-auth enforced"; any other outcome (the exchange reaches an
AS-REP) is read as "roastable". A realm with unusual KDC error behaviour
is the place to double-check it.
