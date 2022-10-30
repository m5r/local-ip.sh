# local-ip.sh

[local-ip.sh](https://www.local-ip.sh) is a DNS service that resolves IP addresses from a specifically formatted hostname.  
It was inspired by [local-ip.co](http://local-ip.co), [sslip.io](https://sslip.io) and [xip.io](https://xip.io)

<!-- TODO: provide certs for ez local dev that requires HTTPS -->

## Usage

```sh
go run ./main.go

dig @localhost 10-0-1-29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost app.10-0-1-29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost foo.bar.10.0.1.29.my.local-ip.sh +short
# 10.0.1.29
dig @localhost 127.0.0.1.my.local-ip.sh +short
# 127.0.0.1
```
