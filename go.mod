module github.com/transferwise/crypto

go 1.14

replace github.com/transferwise/cipher/des => ./des

require (
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.4.2
)
