# local-ip.sh

[local-ip.sh](https://local-ip.sh) is a magic domain name that provides wildcard DNS for any IP address.  
It is heavily inspired by [local-ip.co](http://local-ip.co), [sslip.io](https://sslip.io), and [xip.io](https://xip.io)

## Usage

```sh
go run ./main.go # binds to :53 by default but you can override it by using the `-port` parameter

dig @localhost 10-0-1-29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost app.10-0-1-29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost foo.bar.10.0.1.29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost 127.0.0.1.my.local-ip.sh +short
# 127.0.0.1
```

## How it works

local-ip.sh packs up:
 - an authoritative DNS server that answers queries for the zone `local-ip.sh`
 - a Let's Encrypt client that takes care of obtaining and renewing the wildcard certificate for `*.local-ip.sh` using the DNS-01 challenge
 - an HTTP server that serves the certificate files

It answers queries with the IPv4 address it may find in the subdomain by pattern matching the FQDN.  
It registers an account to Let's Encrypt's ACME server to obtain the wildcard certificate on the first run and then renew
it about a month before it expires. The account file and the associated key used to request a certificate under the `.lego`
directory but the certificate's files are stored in `/certs` at the root of the filesystem. I've done it this way to mount
a persistent storage volume there and keep the files between deployments without tracking them in git but feel free to
change this behavior in [`certs/certs.go`](./certs/certs.go) and in [`http/server.go`](./http/server.go)
if you're planning to self-host it.

The certificate files are served by an HTTP server on the arbitrary port `:9229` that is intentionally not exposed to
the internet. [The website](https://local-ip.sh) is connected to the same private network as the service and serves
as a proxy to access the files securely.

## Self-hosting

I'm currently hosting [local-ip.sh](https://www.local-ip.sh) at [Fly.io](https://fly.io) but you can host the service yourself
if you're into that kind of thing. Note that you will need to edit your domain's glue records so make sure your registrar allows it.

You will essentially need to:
 - replace any occurrence of `local-ip.sh` in `.go` files with your domain
 - replace the hardcoded IP addresses in the `hardcodedRecords` map declared in [`xip.go:37`](./xip/xip.go#L37), the important records to keep are:
   - `A ns.local-ip.sh.` holds both IP addresses pointing to `ns1.` and `ns2.`
   - `A ns1.local-ip.sh.` holds the first IP address pointing to the server hosting local-ip.sh
   - `A ns2.local-ip.sh.` holds the second IP address pointing to the server, exists for redundancy
   - `TXT _acme-challenge.local-ip.sh.` will temporarily hold the value to solve the DNS-01 challenge
 - set your domain's glue records to point to the IP addresses you set for `ns1.` and `ns2.`
 - retrieve the certificate files once the program is up and running
