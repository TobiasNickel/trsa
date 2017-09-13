# trsa
node-forge rsa with an API that you understand.

node-forge is a great module, it offers good encryption. Sadly its API is to complex. This module reduce the API for rsa signing/veriication and encryption/decryption to a minimum of just 6 functions.

 - generateKeyPair() and  generaitKeyPairSync() to create public and private key
 - sign(data, privateKey) to sign data
 - verify(data, publicKey) to verify the source of the data
 - encrypt(data, publicKey) to encrypt something that only the coresponding privateKey can decrypt
 - decrypt(data, privateKey) decrypt data that was encrypted specially for you.

you can use webpack or browserify to use the rsa module in the browser.

