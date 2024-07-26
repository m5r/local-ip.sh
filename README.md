# local-ip.sh

[local-ip.sh](https://local-ip.sh) is a magic domain name that provides wildcard DNS for any IP address.
It is heavily inspired by [local-ip.co](http://local-ip.co), [sslip.io](https://sslip.io), and [xip.io](https://xip.io)

## How it works

local-ip.sh packs up:
 - an authoritative DNS server that answers queries for the zone `local-ip.sh`
 - a Let's Encrypt client that takes care of obtaining and renewing the wildcard certificate for `*.local-ip.sh` and the root certificate for `local-ip.sh` using the [DNS-01 challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
 - an HTTP server that serves the website and the wildcard certificate files

It answers queries with the IPv4 address it may find in the subdomain by pattern matching the FQDN.
It registers an account to Let's Encrypt's ACME server to obtain the wildcard certificate on the first run and then renew it about a month before it expires. The account file and the associated key used to request a certificate under the `./.lego/accounts` directory and the certificate's files are stored in `./.lego/certs`.
It also obtains a separate certificate for the root domain to serve the website through HTTPS. It initially serves the website through HTTP and when the root domain certificate is ready, it redirects all HTTP requests to HTTPS.

## Usage

```sh
go run ./main.go --staging --dns-port 9053 --http-port 9080 --https-port 9443 --domain local-ip.sh --email admin@fake.sh --nameservers 137.66.40.11,137.66.40.12

dig @localhost -p 9053 10-0-1-29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 app.10-0-1-29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 foo.bar.10.0.1.29.local-ip.sh +short
# 10.0.1.29
dig @localhost -p 9053 127.0.0.1.local-ip.sh +short
# 127.0.0.1
```

### Configuration

local-ip.sh can be configured through environment variables or CLI flags

- `XIP_DNS_PORT` or `--dns-port` optional, port for the DNS server, defaults to `53`.
- `XIP_HTTP_PORT` or `--http-port` optional, port for the HTTP server, defaults to `80`.
- `XIP_HTTPS_PORT` or `--https-port` optional, port for the HTTPS server, defaults to `443`.
- `XIP_STAGING` or `--staging` optional, enable to use Let's Encrypt staging environment to obtain certificates, defaults to `false`.
- `XIP_DOMAIN` or `--domain` required, domain name of the server hosting this. It will be used as the zone to answer dns queries for.
- `XIP_EMAIL` or `--email` required, administrator's email address, used to create the ACME account to request certificates from Let's Encrypt and as the `RNAME` value of the SOA record representing the domain administrator's email address.
- `XIP_NAMESERVERS` or `--nameservers` required, comma-separated IPv4 addresses used to answer `A` queries for `nsX.{domain}` where `X` is the index of the address in this list. For example setting `--domain example.com --nameservers 1.2.3.4,9.8.7.6` will answer `1.2.3.4` for `ns1.example.com` and `9.8.7.6` for `ns2.example.com`. All `nsX.{domain}` nameservers will be in the answer for NS queries to the zone.

A [reference docker compose file](./compose.yml) is available for deployments using Docker.

## Self-hosting

I'm currently hosting [local-ip.sh](https://local-ip.sh) at [Fly.io](https://fly.io) but you can host the service yourself if you're into that kind of thing. Note that you will need to edit your domain's glue records so make sure your registrar allows it.

You will essentially need to:
 - set your domain's glue records to point to the IP addresses you will set for `XIP_NAMESERVERS` / `--nameservers`
 - configure `local-ip.sh` with the domain, admin email address, and nameservers
 - ensure you have some sort of persistent storage for the `./.lego` directory, this is where the ACME account and certificate files are stored, you don't want to lose this between deployments
