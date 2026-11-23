# local-ip.sh

[local-ip.sh](https://local-ip.sh) is a magic domain name that provides wildcard DNS for any IP address.
It is heavily inspired by [local-ip.co](http://local-ip.co), [sslip.io](https://sslip.io), and [xip.io](https://xip.io)

## How it works

local-ip.sh packs up:
 - an authoritative DNS server that answers queries for the zone `local-ip.sh`
 - a Let's Encrypt client that takes care of obtaining and renewing the wildcard certificate for `*.local-ip.sh` and the root certificate for `local-ip.sh` using the [DNS-01 challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
 - an HTTP server that serves the website and the wildcard certificate files

It answers a query for the A record of a name that carries an IPv4 address with that address (see [Names](#names)). It registers an account with Let's Encrypt on its first run and keeps two certificates: the wildcard certificate for `*.local-ip.sh`, whose private key is published, and a separate certificate for the root domain `local-ip.sh` that serves the website. The account and the certificates are stored in the state directory (`./state` by default). Each certificate is renewed when a third of its lifetime remains (half of it for a certificate valid less than 10 days), or earlier when Let's Encrypt asks for it. The website is served over HTTP until the root domain's certificate exists, and HTTP requests are redirected to HTTPS from then on.

## Usage

```sh
go run ./main.go --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory --dns-port 9053 --http-port 9080 --https-port 9443 --domain local-ip.sh --zone-file zones/local-ip.sh.zone --email admin@fake.sh

dig @localhost -p 9053 10-0-1-29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 app-10-0-1-29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 app.10-0-1-29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 foo.bar.10.0.1.29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 127.0.0.1.local-ip.sh +short
# 127.0.0.1
```

### Names

A name carries an address when the labels in front of the domain hold four numbers from 0 to 255, written without leading zeros and joined either by hyphens or by dots, with a hyphen, a dot or an end of the name on each side:

| Name | Resolves to |
| --- | --- |
| `10-0-1-29.local-ip.sh` | 10.0.1.29 |
| `app-10-0-1-29.local-ip.sh`, `10-0-1-29-app.local-ip.sh` | 10.0.1.29 |
| `app.10-0-1-29.local-ip.sh`, `foo.bar.10.0.1.29.local-ip.sh` | 10.0.1.29 |
| `10.0.1.29.local-ip.sh` | 10.0.1.29 |
| `10-0-1-29.app.local-ip.sh`, `10.0.1.29.app.local-ip.sh` | 10.0.1.29 |

When a name holds several addresses, one written with hyphens is preferred to one written with dots, and among those the first from the left counts. A number directly in front of an address is therefore read as part of it: `web-1-10-0-1-29.local-ip.sh` resolves to 1.10.0.1, so write `web1-10-0-1-29.local-ip.sh`. Letter case does not matter. `10-0-1.local-ip.sh` (three numbers), `10-0-01-29.local-ip.sh` (a leading zero) and `10-0-1-256.local-ip.sh` carry no address.

The wildcard certificate is for `*.local-ip.sh`, which matches exactly one label in front of the domain: `10-0-1-29.local-ip.sh` and `app-10-0-1-29.local-ip.sh` can be served over HTTPS with it. It does not cover a name with two or more labels in front of `local-ip.sh`, such as `app.10-0-1-29.local-ip.sh` or any address written with dots.

### Configuration

local-ip.sh can be configured through environment variables or CLI flags

- `XIP_DNS_PORT` or `--dns-port` optional, port for the DNS server, over UDP and TCP, defaults to `53`.
- `XIP_HTTP_PORT` or `--http-port` optional, port for the HTTP server, defaults to `80`.
- `XIP_HTTPS_PORT` or `--https-port` optional, port for the HTTPS server, defaults to `443`.
- `XIP_DOMAIN` or `--domain` required, the domain the server answers DNS queries for, and the origin of the zone file.
- `XIP_ZONE_FILE` or `--zone-file` required, path to the zone file, which holds every record the server stores (see [Records](#records)).
- `XIP_EMAIL` or `--email` optional, contact address of the ACME account the certificates are requested with. When given it must be a bare address such as `admin@example.com`; without it the account has no contact.
- `XIP_STATE_DIR` or `--state-dir` optional, directory where the ACME account and the certificates are stored, defaults to `./state`.
- `XIP_ACME_DIRECTORY` or `--acme-directory` optional, HTTPS URL of the ACME directory of the certificate authority, defaults to Let's Encrypt production, `https://acme-v02.api.letsencrypt.org/directory`. Let's Encrypt's staging environment, `https://acme-staging-v02.api.letsencrypt.org/directory`, issues certificates no browser trusts, under much higher rate limits. The authority's API is verified against the system's trusted roots; on Linux, `SSL_CERT_FILE` names a PEM bundle that is read in place of the system's bundle file, while the system's certificate directories are still read.
- `XIP_ACME_PROFILE` or `--acme-profile` optional, ACME certificate profile to request, for example `shortlived` for Let's Encrypt's 160-hour certificates, defaults to none, which lets the certificate authority choose.
- `XIP_LOG_LEVEL` or `--log-level` optional, `trace`, `debug`, `info`, `warn` or `error`, defaults to `info`.
- `XIP_LOG_FORMAT` or `--log-format` optional, `auto`, `json` or `console`, defaults to `auto`, which is `console` on a terminal and `json` otherwise.
- `XIP_LOG_FILE` or `--log-file` optional, also append logs as JSON to this file, rotated at 1 MB inside its directory, which must stay writable. No file is written by default.

At `debug` and `trace` level the server logs each query it answers with the name that was asked for, which exposes the internal host names of the people using the instance and slows the server down; use these levels for troubleshooting only. The ACME client's lines go through the same logger, with the field `component` set to `acme`.

### Certificates

A failed certificate order never stops the server: DNS keeps answering, the certificate in use stays in use, and the order is retried after 5 minutes, then at growing intervals up to 6 hours, never before the time the certificate authority asks to wait. Each failure is logged at `error` level with the certificate authority's explanation.

The two certificates are ordered one after the other, and each challenge value is published for 75 seconds before validation is requested. On a first start the website therefore answers over HTTPS after about a minute and a half, and `/server.pem` and `/server.key` answer `503` for about three minutes.

`/server.pem` and `/server.key` are two requests: a client that fetches one before a renewal and the other after it holds a certificate and a key that do not match, so check that the key fits the certificate and fetch both again if it does not.

Sending `SIGUSR1` to the process renews both certificates now: `docker kill --signal=USR1 <container>`, or on Fly, `POST /v1/apps/<app>/machines/<id>/signal` with `{"signal": "SIGUSR1"}` on the Machines API.

Upgrading from a version that kept its files in `./.lego`: those files are not read. The server registers a new account and orders both certificates on its first start, so HTTPS and the published certificate files are unavailable for the durations above, longer if Let's Encrypt cannot be reached or refuses. The volume has to be mounted at the state directory, and the old `accounts` and `certs` directories can be deleted once going back to the previous version is no longer wanted.

### Records

The zone file holds every record the server stores, in RFC 1035 syntax, with names relative to the domain. This is a complete file for `--domain example.com`, with two name servers inside the domain and the address of the website:

```
; zone file for example.com, names are relative to the domain
$TTL 300
@      3600  SOA    ns1 hostmaster 2026112301 900 900 1800 3600
@      3600  NS     ns1
@      3600  NS     ns2
ns1    3600  A      192.0.2.53
ns2    3600  A      198.51.100.53
@      3600  A      192.0.2.80
```

Other records go below them; these lines send the domain's mail elsewhere and point a name at another host:

```
@     MX     10 mail.example.net.
@     TXT    "v=spf1 include:example.net ~all"
www   CNAME  site.example.net.
```

The rules of the file:

- A record without a TTL takes the one set by `$TTL` or, as usual in zone files, the TTL of the record before it, and 300 seconds when neither exists; stating `$TTL` at the top keeps a TTL written on one record from becoming the default of the next. A TTL is at most 2147483647, the largest RFC 2181 lets a resolver keep as written. The records of one name and type share one TTL.
- The domain has exactly one SOA record, served as written. Its serial is yours to maintain if you want it to mean something: nothing in this server reads it, since zone transfers are refused.
- The domain has at least one NS record. A name server named inside the domain must own an A or AAAA record in the file, must be outside every delegated subdomain, and must not carry an address in its name, since such a name cannot own records. A name server outside the domain needs nothing more. The answer to an NS query for the domain carries the A and AAAA records of its name servers inside the domain in the additional section.
- The other records are A, AAAA, CAA, CNAME, MX, SRV and TXT records at the domain or below it. None may be at `_acme-challenge` or at a name that carries an address, a CNAME record must be alone at its name, point outside the domain and not be at the domain itself, and the target of an MX or SRV record inside the domain and outside every delegated subdomain must own an address record or carry an address in its name, and must own no CNAME record; the domain itself has an address only when the file gives it an A or AAAA record.
- Every answer must fit in a DNS message together with the OPT record of an EDNS reply, which leaves 65524 octets.
- The `$GENERATE` directive is not supported: no line of the file may begin with `$GENERATE`.

Anything else stops the server at startup with an error naming the file and the record, or the line for `$GENERATE`.

The server computes two kinds of answers itself, and the file declares neither: the A record of a name that carries an address, and the TXT records at `_acme-challenge`. A query for another type at an alias such as `www` gets its CNAME record; any other name without the records asked for gets an empty answer with the domain's SOA record in the authority section, and never NXDOMAIN unless it is too long to have any name below it. A query for `ANY` at a name with records gets the HINFO record of RFC 8482 instead of the records, or the CNAME record at an alias. There are no zone transfers.

The server answers over UDP and TCP: a UDP reply holds 512 octets, or with EDNS the size the query advertises, taken between 512 and 1232 octets, and a larger answer is truncated to whole records with the TC flag set, so that the resolver asks again over TCP and gets it whole.

The address a name carries has a TTL of one day. Records from the zone file keep the TTL the file gives them. A negative answer carries the SOA record with the smaller of its TTL and its MINIMUM field as its TTL, and a resolver may keep the empty answer that long. Answers at `_acme-challenge`, negative ones included, have a TTL of 0, so that no resolver keeps a stale challenge. A resolver that asked for a name before a record was added there, such as a new DKIM selector or a first CAA or MX record, can keep its empty answer for that negative TTL, so publish a record that long before anything depends on it. Changing the address of a name server also needs the glue records at the domain's registry changed and the old address kept answering while resolvers still use it: the delegation in the parent zone has its own TTL, which the zone file does not set.

### Delegating a subdomain

With `--domain example.com`, these lines of the zone file delegate `sub.example.com` to a name server that lives inside it and to one outside the domain:

```
sub      NS  ns1.sub
sub      NS  ns.example.net.
ns1.sub  A   192.0.2.1
```

Delegations are NS records below the domain with A or AAAA glue records for their name servers: a delegated name server must be inside the delegated subdomain, with glue, or outside the domain entirely, nested delegations and a delegation of `_acme-challenge` are refused, and nothing but glue may be declared at or below a delegated name. Glue must not hold an address the zone file gives one of the domain's own name servers, since the delegation would point back at this server.

For any query at or below `sub.example.com`, whatever its type, the server answers with a referral instead of answering itself: no answer, the AA flag clear, the delegation's NS records in the authority section and the glue addresses in the additional section (a DS query for `sub.example.com` itself is still answered by this server, as DS records belong to the parent zone).

A delegation takes every name at or below the label away from the server, including names that carry an address: with the lines above, `10-0-0-1.sub.example.com` gets the referral, not `10.0.0.1`. Such a name that a resolver asked for before the delegation was added can keep resolving to its address in that resolver's cache for up to a day, the TTL of the address a name carries. Only delegate labels you have set aside for the purpose. On the hosted instance, labels directly below `local-ip.sh` that start with `xip-` are reserved for the project, and names under a reserved label are not part of the service.

A [reference docker compose file](./compose.yml) is available for deployments using Docker.

## Testing

- `make check` fails if any Go file is not `gofmt`-clean, then runs `go vet` and `go test -race` on every package. It only looks at files git knows about (tracked, or untracked and not ignored), and it needs no network: the certificate tests run an ACME server inside the test process, and the end-to-end suites are skipped unless `E2E_FLY_CONFIG` or `E2E_COMPOSE_FILE` is set. The Gitea workflow in `.gitea/workflows/check.yml` runs `make check` on every push.
- `make e2e` runs the live end-to-end suite against production, described by `fly.toml`; `make e2e FLY_CONFIG=<file>` runs it against the deployment another Fly config describes.
- `make e2e-local` runs the same suite, and a lifecycle test, against the server built from the checkout, in the Docker rig of `e2e/rig/compose.yml`, with [Pebble](https://github.com/letsencrypt/pebble) as its certificate authority. The lifecycle test sends `SIGUSR1` and checks that both certificates change, with fresh keys and challenges validated again, while DNS keeps answering and the process keeps running, then restarts the container and checks that the same certificates are served again.

The live suite reads the domain and the zone file from the Fly config file, sends its DNS queries to the IPv4 addresses the zone file gives the name servers inside the domain and reaches the website at the IPv4 addresses of the domain, and verifies the certificates against the system's trusted roots. It only reads from the target: it sends DNS queries to each nameserver and HTTP GET requests to the website, including the published wildcard certificate and key, which it keeps in memory. It also queries the public resolvers `1.1.1.1`, `8.8.8.8` and `9.9.9.10`, all of which must answer. DNS queries that get no response are retried with growing pauses, and every lost attempt is reported in the test output. The suite reads the zone file delivered through the matching `[[files]]` entry and checks that every nameserver answers queries at and below each delegated name with a referral to the declared name servers and glue, and answers every record set the file declares outside its delegations with exactly the declared records. The suite refuses a target whose zone file declares a record at, or delegates, one of the names it probes, and names the name and the declaration.

Prerequisites for the live suite: Go, outbound IPv4 UDP port 53, TCP port 53, TCP port 80 and TCP port 443, and the ability to listen on a loopback port.

The rig is the compose project `local-ip-e2e`: the server, for the domain `local-ip.test` with the zone file `e2e/rig/zone`, and Pebble, on a network of their own with a fixed private subnet. The test reads the server's environment and bind mounts from `docker compose config`, so it expects what compose runs. It removes the project with its volumes before it starts, so a run interrupted earlier does not leak into the next one, and again when it ends, after printing the logs of both containers if it failed; it refuses to run any other project. Nothing is published on host ports: the test reaches both containers at their addresses on that network, which needs a Docker Engine running natively on the Linux host, not Docker Desktop or a remote Docker context. The public resolvers are skipped, since nothing delegates `local-ip.test`. The certificates are verified against the root Pebble generates at its start, which the test fetches from Pebble's management API. A run builds the image and waits for four orders of 75 seconds each, two at the first start and two for the renewal.

Prerequisites for the rig: Go, Docker Engine with the compose plugin on a Linux host, no other network on the subnet `e2e/rig/compose.yml` gives the rig, and the network access the image build needs.

The compose file pins Pebble's image by version and index digest, read like the Dockerfile's bases with `docker buildx imagetools inspect ghcr.io/letsencrypt/pebble:<version>`; the version is that of the Pebble module in `go.mod`, and `e2e/rig/pebble.minica.pem` is copied from the same release's `test/certs` whenever the version moves.

## Self-hosting

I'm currently hosting [local-ip.sh](https://local-ip.sh) at [Fly.io](https://fly.io) but you can host the service yourself if you're into that kind of thing. Note that you will need to edit your domain's glue records so make sure your registrar allows it.

You will essentially need to:
 - write the zone file (see [Records](#records)): the SOA record, the NS records of your name servers and, for those inside the domain, their A and AAAA records, and the A records of the domain for the website
 - set your domain's glue records at the registry to the addresses the zone file gives the name servers inside the domain, so that the parent zone and the file agree
 - configure `local-ip.sh` with the domain, the zone file and, if you want the ACME account to have a contact, an email address
 - ensure you have some sort of persistent storage for the state directory (`./state`, `/local-ip/state` in the Docker image), this is where the ACME account and certificate files are stored, you don't want to lose this between deployments
 - while trying the setup out, set `XIP_ACME_DIRECTORY` / `--acme-directory` to Let's Encrypt's staging environment so that failed attempts do not count against the production rate limits, then remove it: the account and the certificates of each authority are kept apart in the state directory, so the next start orders certificates from production

The Dockerfile pins both base images by the digest of their multi-arch index; to move them forward, read each new digest from the first `Digest:` line of `docker buildx imagetools inspect golang:<version>-trixie` and `docker buildx imagetools inspect gcr.io/distroless/static-debian13`, and write the version and the digests into its `FROM` lines; the `go` line of `go.mod` moves with the Go version, since the image build refuses an older Go than that line and the workflow installs that version.
