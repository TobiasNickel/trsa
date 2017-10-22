var rsa = require('./rsa');


(async function() {
    const aliceKeyPair = await rsa.generateKeyPair({ bits: 512 });
    console.log(aliceKeyPair.privateKey)
    var message = "Lorem.";
    var encryptedMessage = rsa.encrypt(message, aliceKeyPair.publicKey);
    var decryptedMessage = rsa.decrypt(encryptedMessage, aliceKeyPair.privateKey);
    console.assert(message === decryptedMessage, "encrypt decrypted should be the same");
    var signature = rsa.sign(message, aliceKeyPair.privateKey);
    console.log({ message })
    console.log('signature', signature);
    console.assert(rsa.verify(message, signature, aliceKeyPair.publicKey), "invalid signature");
    console.assert(!rsa.verify(message + "f", signature, aliceKeyPair.publicKey), "invalid signature");
})().catch(err => console.log(err));