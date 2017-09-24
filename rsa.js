/**
 * I saw the node-forge API is very uglu, the rsa module will just provide a nicer API.
 * - tasks should be possible to finish in one call
 * - async functions should return a promise
 * - keys, signatures and encrypted data should be represented stringifyable data not as complex objects
 */

var forge = require('node-forge');

var rsa = forge.pki.rsa;

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
        if (!options.workers) options.workers = 2;

        // options is like: { bits: 2048, workers: 2 }
        rsa.generateKeyPair(options, function(err, { privateKey, publicKey }) {
            if (err) {
                reject(err);
                return;
            }
            // keypair.privateKey, keypair.publicKey 
            const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
            const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
            // forge.pki.privateKeyFromPem(forge.pki.privateKeyToPem(m.keypair.privateKey));
            // forge.pki.publicKeyFromPem(forge.pki.publicKeyToPem(m.keypair.publicKey))
            resolve({ privateKey: privateKeyPem, publicKey: publicKeyPem });
        });
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
    if (!options.workers) options.workers = 2;
    var { privateKey, publicKey } = rsa.generateKeyPair(options);
    privateKey = forge.pki.privateKeyToPem(privateKey);
    publicKey = forge.pki.publicKeyToPem(publicKey);
    return { privateKey, publicKey };
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function sign(data, privateKey) {
    const md = forge.md.sha1.create();
    privateKey = forge.pki.privateKeyFromPem(privateKey);
    md.update(data, 'utf8');
    const signature = privateKey.sign(md);
    return signature; //JSON.stringify(signature) //new Buffer(signature).toString('base64');
}

/**
 * 
 * @param {string} data 
 * @param {string} signature 
 * @param {string} publicKey 
 * @return {boolean}
 */
function verify(data, signature, publicKey) {
    //signature = JSON.parse(signature) //new Buffer(signature, 'base64').toString('ascii')
    publicKey = forge.pki.publicKeyFromPem(publicKey);
    const md = forge.md.sha1.create();
    md.update(data, 'utf8');
    const bytes = md.digest().bytes()
    try {
        return publicKey.verify(bytes, signature);
    } catch (err) {
        // wrong signatures are not considered a error
        // it is one possible outcome of a verification process
        return false;
    }
}

/**
 * 
 * @param {string} data 
 * @param {string} publicKey 
 * @return {string}
 */
function encrypt(data, publicKey) {
    publicKey = forge.pki.publicKeyFromPem(publicKey);
    return publicKey.encrypt(data);
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function decrypt(data, privateKey) {
    privateKey = forge.pki.privateKeyFromPem(privateKey);
    return privateKey.decrypt(data);
}

module.exports = {
    generateKeyPair,
    generateKeyPairSync,
    sign,
    verify,
    encrypt,
    decrypt,
};