module github.com/transferwise/crypto

go 1.14

replace github.com/transferwise/cipher/des => ./des

replace github.com/transferwise/cipher/aes => ./aes

replace github.com/transferwise/cipher/kek => ./kek

require (
	github.com/hashicorp/vault v1.4.2 // indirect
	github.com/transferwise/cipher/aes v0.0.0-00010101000000-000000000000 // indirect
	github.com/transferwise/cipher/des v0.0.0-00010101000000-000000000000 // indirect
	github.com/transferwise/cipher/kek v0.0.0-00010101000000-000000000000 // indirect
)
