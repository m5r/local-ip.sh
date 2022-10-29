# local-ip.sh

[local-ip.sh](https://www.local-ip.sh) is a DNS service that resolves IP addresses from a specifically formatted hostname.  
It was inspired by [local-ip.co](http://local-ip.co) and 

<!-- TODO: provide certs for ez local dev that requires HTTPS -->

## Usage

```sh
$ dig 10-0-1-29.my.local-ip.sh +short
10.0.1.29
$ dig app.10-0-1-29.my.local-ip.sh +short
10.0.1.29
$ dig foo.bar.10.0.1.29.my.local-ip.sh +short
10.0.1.29
$ dig 127.0.0.1.my.local-ip.sh +short
127.0.0.1
```
