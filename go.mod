module github.com/dnsgateway/dnsgate

go 1.27

require (
	github.com/dnsgateway/dnsprovider v0.0.0-20261008174015-be2eab62a2a4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
)

require (
	github.com/cloudflare/cloudflare-go/v7 v7.12.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
)

replace github.com/dnsgateway/dnsprovider => ../dnsprovider
