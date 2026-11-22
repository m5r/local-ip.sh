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
go run ./main.go --staging --dns-port 9053 --http-port 9080 --https-port 9443 --domain local-ip.sh --email admin@fake.sh --nameservers 137.66.40.11,137.66.40.12

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
- `XIP_STAGING` or `--staging` optional, enable to use Let's Encrypt staging environment to obtain certificates, defaults to `false`.
- `XIP_DOMAIN` or `--domain` required, domain name of the server hosting this. It will be used as the zone to answer dns queries for.
- `XIP_EMAIL` or `--email` required, administrator's email address, used to create the ACME account to request certificates from Let's Encrypt and as the `RNAME` value of the SOA record representing the domain administrator's email address.
- `XIP_NAMESERVERS` or `--nameservers` required, comma-separated IPv4 addresses used to answer `A` queries for `nsX.{domain}` where `X` is the index of the address in this list. For example setting `--domain example.com --nameservers 1.2.3.4,9.8.7.6` will answer `1.2.3.4` for `ns1.example.com` and `9.8.7.6` for `ns2.example.com`. All `nsX.{domain}` nameservers will be in the answer for NS queries to the zone.
- `XIP_STATE_DIR` or `--state-dir` optional, directory where the ACME account and the certificates are stored, defaults to `./state`.
- `XIP_ACME_PROFILE` or `--acme-profile` optional, ACME certificate profile to request, for example `shortlived` for Let's Encrypt's 160-hour certificates, defaults to none, which lets the certificate authority choose.
- `XIP_ZONE_FILE` or `--zone-file` optional, path to a zone file in RFC 1035 syntax declaring delegations of subdomains to other name servers and records the server answers itself. Names are relative to the domain; a record without a TTL takes the one set by `$TTL` or, as usual in zone files, the TTL of the record before it, and 300 seconds when neither exists. Delegations are NS records below the apex with A/AAAA glue records for their name servers: a delegated name server must be inside the delegated subdomain, with glue, or outside the domain entirely, glue addresses must not be this server's own nameserver addresses, and nothing else may be declared at or below a delegated name. Records are A, AAAA, CAA, CNAME, MX, SRV and TXT records at the domain or below it, with these restrictions: none at the `nsX` names, at `_acme-challenge` or at a name that carries an address, no A or CNAME record at the domain itself, a CNAME record alone at its name and pointing outside the domain, an MX or SRV target inside the domain and outside every delegated subdomain must have an address and no CNAME record, and every answer must fit in a DNS message together with the OPT record of an EDNS reply, which leaves 65524 octets. Anything else stops the server at startup with an error naming the file and the record. The `$GENERATE` directive is not supported: no line of the file may begin with `$GENERATE`, and one that does stops the server at startup with an error naming the file and the line. The server answers over UDP and TCP: a UDP reply holds 512 octets, or with EDNS the size the query advertises, taken between 512 and 1232 octets, and a larger answer is truncated to whole records with the TC flag set, so that the resolver asks again over TCP and gets it whole.
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

### Delegating a subdomain

With `--domain example.com`, this zone file delegates `sub.example.com` to a name server that lives inside it:

```
; zone file for example.com, names are relative to the domain
sub      NS  ns1.sub
sub      NS  ns.example.net.
ns1.sub  A   192.0.2.1
```

For any query at or below `sub.example.com`, whatever its type, the server answers with a referral instead of answering itself: no answer, the AA flag clear, the delegation's NS records in the authority section and the glue addresses in the additional section (a DS query for `sub.example.com` itself is still answered by this server, as DS records belong to the parent zone).

A delegation takes every name at or below the label away from the server, including names that carry an address: with the zone file above, `10-0-0-1.sub.example.com` gets the referral, not `10.0.0.1`. Only delegate labels you have set aside for the purpose. On the hosted instance, labels directly below `local-ip.sh` that start with `xip-` are reserved for the project: `xip-staging.local-ip.sh` is delegated to its test instance, and names under a reserved label are not part of the service.

### Records

With `--domain example.com`, this zone file sends the domain's mail elsewhere and points a name at another host:

```
; zone file for example.com, names are relative to the domain
@     MX     10 mail.example.net.
@     TXT    "v=spf1 include:example.net ~all"
www   CNAME  site.example.net.
```

The server answers by itself for the domain's SOA, NS and A records, for the addresses of its name servers, and for the address of every name that carries one. A query for another type at an alias such as `www` gets its CNAME record; any other name without the records asked for gets an empty answer with the domain's SOA record in the authority section, and never NXDOMAIN unless it is too long to have any name below it. A query for `ANY` at a name with records gets the HINFO record of RFC 8482 instead of the records, or the CNAME record at an alias. There are no zone transfers.

A [reference docker compose file](./compose.yml) is available for deployments using Docker.

## Testing

- `make check` fails if any Go file is not `gofmt`-clean, then runs `go vet` and `go test -race` on every package. It only looks at files git knows about (tracked, or untracked and not ignored), and it needs no network: the certificate tests run an ACME server inside the test process, and the live suites are skipped unless `E2E_FLY_CONFIG` or `E2E_LIFECYCLE_FLY_CONFIG` is set.
- `make e2e` runs the live end-to-end suite against the staging deployment described by `fly.staging.toml` (the default).
- `make e2e FLY_CONFIG=fly.toml` runs the same suite against production.
- `make e2e-lifecycle` asks the staging deployment for a certificate renewal through the Fly Machines API and checks that both certificates change while DNS keeps answering, then restarts the machine and checks that the same certificates are served again. It needs `FLY_API_TOKEN`, preferably a token limited to the staging app (`fly tokens create deploy -a local-ip-staging -x 1h` prints one), and it refuses every deployment other than the staging one.

The live suite reads the zone, nameserver addresses, admin email and certificate authority from the Fly config file. It only reads from the target: it sends DNS queries to each nameserver and HTTP GET requests to the website, including the published wildcard certificate and key, which it keeps in memory. It also queries the public resolvers `1.1.1.1`, `8.8.8.8` and `9.9.9.10`, all of which must answer. DNS queries that get no response are retried with growing pauses, and every lost attempt is reported in the test output. When the Fly config sets `XIP_ZONE_FILE`, the suite reads the zone file delivered through the matching `[[files]]` entry and checks that every nameserver answers queries at and below each delegated name with a referral to the declared name servers and glue, and answers every record set the file declares outside its delegations with exactly the declared records. The suite refuses a target whose zone file declares a record at, or delegates, one of the names it probes, and names the name and the declaration.

Prerequisites for the live suite: Go, outbound IPv4 UDP port 53, TCP port 53, TCP port 80 and TCP port 443, and the ability to listen on a loopback port.

## Self-hosting

I'm currently hosting [local-ip.sh](https://local-ip.sh) at [Fly.io](https://fly.io) but you can host the service yourself if you're into that kind of thing. Note that you will need to edit your domain's glue records so make sure your registrar allows it.

You will essentially need to:
 - set your domain's glue records to point to the IP addresses you will set for `XIP_NAMESERVERS` / `--nameservers`
 - configure `local-ip.sh` with the domain, admin email address, and nameservers
 - ensure you have some sort of persistent storage for the state directory (`./state`, `/local-ip/state` in the Docker image), this is where the ACME account and certificate files are stored, you don't want to lose this between deployments

The Dockerfile pins both base images by the digest of their multi-arch index; to move them forward, read each new digest from the first `Digest:` line of `docker buildx imagetools inspect golang:<version>-trixie` and `docker buildx imagetools inspect gcr.io/distroless/static-debian13`, and write the version and the digests into its `FROM` lines.
