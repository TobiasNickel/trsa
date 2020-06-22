# trsa
node-rsa rsa with an API that you understand.

node-rsa is a great module, it offers good encryption. Sadly its API is to complex. This module reduce the API for rsa signing / verification and encryption/decryption to a minimum of just 6 functions. Also it let you work with plane old javascript objects and data types. You don't need to hassle with internal classes.

 - generateKeyPair({bits: 512}) to create 512 bit public and private key
 - sign(data, privateKey) to sign data
 - verify(data, signature, publicKey) to verify the source of the data
 - encrypt(data, publicKey) to encrypt something that only the corresponding privateKey can decrypt
 - decrypt(data, privateKey) decrypt data that was encrypted specially for you.

you can use webpack or browserify to use the rsa module in the browser. And the now it has a corresponding implementation in golang.

