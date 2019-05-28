module github.com/trustbloc/fabric-peer-test-common

replace github.com/hyperledger/fabric => github.com/trustbloc/fabric-mod v0.0.0-20190507140713-ae22bce54dfb

replace github.com/hyperledger/fabric/extensions => github.com/trustbloc/fabric-mod/extensions v0.0.0-20190507140713-ae22bce54dfb

replace github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric => github.com/trustbloc/fabric-sdk-go-ext/fabric v0.0.0-20190528182243-b95c24511993

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/fsouza/go-dockerclient v1.3.0
	github.com/hyperledger/fabric v1.4.1
	github.com/hyperledger/fabric-sdk-go v1.0.0-alpha5.0.20190429134815-48bb0d199e2c
	github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric v0.0.0-20190429134815-48bb0d199e2c
	github.com/pkg/errors v0.8.1
	github.com/spf13/viper v1.0.2
	github.com/stretchr/testify v1.3.0
)
