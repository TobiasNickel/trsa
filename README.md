# trsa
node-forge rsa with an API that you understand.

node-forge is a great module, it offers good encryption. Sadly its API is to complex. This module reduce the API for rsa signing/veriication and encryption/decryption to a minimum of just 6 functions.

 - generaitKeyPair({bits:512}) to create a 512 bits public and private keys
 - sign(data, privateKey) to sign data
 - verify(data, signature, publicKey) to verify the source of the data
 - encrypt(data, publicKey) to encrypt something that only the coresponding privateKey can decrypt
 - decrypt(data, privateKey) decrypt data that was encrypted specially for you.

you can use webpack or browserify to use the rsa module in the browser.

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

