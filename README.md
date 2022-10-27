# local-ip.dev

[local-ip.dev](https://www.local-ip.dev) is a DNS service that resolves IP addresses from a specifically formatted hostname.  
It was inspired by [local-ip.co](http://local-ip.co) and 

<!-- TODO: provide certs for ez local dev that requires HTTPS -->

## Usage

```sh
$ dig 10-0-1-29.my.local-ip.dev +short
10.0.1.29
$ dig 127.0.0.1.my.local-ip.dev +short
127.0.0.1
```
