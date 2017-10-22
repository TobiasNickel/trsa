/**
 * I saw the node-forge API is very uglu, the rsa module will just provide a nicer API.
 * - tasks should be possible to finish in one call
 * - async functions should return a promise
 * - keys, signatures and encrypted data should be represented stringifyable data not as complex objects
 */

var NodeRSA = require('node-rsa');

/**
 * @typedef KeyPair 
 * @property {string} publicKey 
 * @property {string} privateKey 
 **/

/**
 * @typedef GenerateOptions 
 * @property {number} [bits] default 2048
 * @property {number} [workers] default 2 
 **/

/**
 * 
 * @param {GenerateOptions} [options]
 * @return {Promise<KeyPair>}
 */
function generateKeyPair(options) {
    if (!options) options = {};
    return new Promise((resolve, reject) => {
        if (!options.bits) options.bits = 2048; // 4096;
        var key = new NodeRSA({ b: options.bits });


        // keypair.privateKey, keypair.publicKey 
        const privateKeyPem = key.exportKey("private");
        const publicKeyPem = key.exportKey("public");
        // forge.pki.privateKeyFromPem(forge.pki.privateKeyToPem(m.keypair.privateKey));
        // forge.pki.publicKeyFromPem(forge.pki.publicKeyToPem(m.keypair.publicKey))
        resolve({ privateKey: privateKeyPem, publicKey: publicKeyPem });
        return key;
    });
}

/**
 * 
 * @param {GenerateOptions} [options]
 * @return {KeyPair} 
 */
const generateKeyPairSync = function(options) {
    if (!options) options = {};
    if (!options.bits) options.bits = 2048; // 4096;
    var key = new NodeRSA({ b: options.bits });


    // keypair.privateKey, keypair.publicKey 
    const privateKeyPem = key.exportKey("private");
    const publicKeyPem = key.exportKey("public");
    // forge.pki.privateKeyFromPem(forge.pki.privateKeyToPem(m.keypair.privateKey));
    // forge.pki.publicKeyFromPem(forge.pki.publicKeyToPem(m.keypair.publicKey))
    return { privateKey: privateKeyPem, publicKey: publicKeyPem };
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function sign(data, privateKey) {
    var key = new NodeRSA(privateKey, "private");
    return key.sign(data, 'hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} signature 
 * @param {string} publicKey 
 * @return {boolean}
 */
function verify(data, signature, publicKey) {
    //console.log({ data, signature, publicKey })
    var key = new NodeRSA(publicKey, "public");
    return key.verify(data, signature, undefined, 'hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} publicKey 
 * @return {string}
 */
function encrypt(data, publicKey) {
    var key = new NodeRSA(publicKey, "public");
    //console.log('key.isPrivate();', key.isPrivate())
    return key.encrypt(data, "buffer").toString('hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function decrypt(data, privateKey) {
    var key = new NodeRSA(privateKey, "private");
    return key.decrypt(Buffer.from(data, 'hex')).toString();
}

module.exports = {
    generateKeyPair,
    generateKeyPairSync,
    sign,
    verify,
    encrypt,
    decrypt,
    sha256,
};

function signatureToHex(signature) {
    return signature.split('').map(c => {
        const code = c.charCodeAt(0);
        return (code < 16 ? '0' : '') + code.toString(16)
    }).join('');
}

function hexToSignature(hex) {
    const tuples = [];
    for (var i = 0; i < hex.length; i += 2) {
        tuples.push(hex[i] + hex[i + 1]);
    }
    return tuples.map(t => String.fromCharCode(parseInt(t, 16))).join('');
};

function sha256(data) {
    const md = forge.md.sha256.create();
    md.update(data);
    return md.digest().toHex();
}