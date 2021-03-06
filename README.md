# trsa
node-rsa rsa with an API that you understand.

node-rsa is a great module, it offers good encryption. Sadly its API is to complex. This module reduce the API for rsa signing / verification and encryption/decryption to a minimum of just 6 functions. Also it let you work with plane old javascript objects and data types. You don't need to hassle with internal classes.

 - generateKeyPair({bits: 512}) to create 512 bit public and private key
 - sign(data, privateKey) to sign data
 - verify(data, signature, publicKey) to verify the source of the data
 - encrypt(data, publicKey) to encrypt something that only the corresponding privateKey can decrypt

 - decrypt(data, privateKey) decrypt data that was encrypted specially for you.

you can use webpack or browserify to use the rsa module in the browser. And the now it has a corresponding implementation in golang.

```js
const rsa = require('trsa')
const keypair = rsa.generateKeyPair({bits:512});

// encryption
const messageForAlice = rsa.encrypt('Hallo, this is Bob. I have something to tell you.', keyPair.publicKey);
const decryptedMessage = rsa.decrypt(messageForAlice, keypair.privateKey);

// signature
const statement = "very tough statement";
const signature = rsa.sign(statement, keypair.privateKey);
const isSigned = rsa.verify(statement, signature, keypair.publicKey);

// save key: using node-rsa directly, this is not possible so easy ! !
// as you see, that you can easily return the key as it is, to a client, without any extra transformation.
fs.writeKeySync('./keyFile.json', JSON.stringify(keypair));

```

# GOLANG
For golang you simple import `github.com/tobiasnickel/trsa/golang/trsa` or run the following command for installation:
```sh
go get github.com/tobiasnickel/trsa/golang/trsa
```
and then you can do the same as before:
```go
package main

import (
	"fmt"
	"io/ioutil"

	"github.com/tobiasnickel/trsa/golang/trsa"
)

func main() {
	publicKey, privateKey, err := trsa.GenerateKeys(2048)
	if err != nil {
		fmt.Println(err)
		return
	}

	golangMessage := []byte("Hallo Javascript from Golang !!!")
    
	encryptedMessage, err := trsa.Encrypt(golangMessage, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
    decryptedMessage, err := trsa.Decrypt(encryptedMessage, privateKey) 
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("decrypted message:", string(decryptedMessage));
	signature, err := trsa.Sign(golangMessage, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = trsa.Verify(golangMessage, signature, publicKey);
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("done")
}
```

