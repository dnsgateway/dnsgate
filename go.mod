module github.com/dnsgateway/dnsgate

go 1.27

require (
	github.com/dnsgateway/dnsprovider v0.0.0-20261008174015-be2eab62a2a4
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/cloudflare/cloudflare-go/v7 v7.12.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)

replace github.com/dnsgateway/dnsprovider => ../dnsprovider
