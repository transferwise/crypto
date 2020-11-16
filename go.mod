module github.com/transferwise/crypto

go 1.14

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20201112134528-b4bfec6bba36

require (
	github.com/ProtonMail/gopenpgp/v2 v2.1.0
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.4.2
)
