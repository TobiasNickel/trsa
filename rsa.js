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
 **/

/**
 * 
 * @param {GenerateOptions} [options]
 * @return {KeyPair} 
 */
const generateKeyPair = function(options) {
    if (!options) options = {};
    if (!options.bits) options.bits = 2048; // 4096;
    var key = new NodeRSA({ b: options.bits });

    const privateKeyPem = key.exportKey('private');
    const publicKeyPem = key.exportKey('public');
    return { privateKey: privateKeyPem, publicKey: publicKeyPem };
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function sign(data, privateKey) {
    var key = new NodeRSA(privateKey, 'private');
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
    var key = new NodeRSA(publicKey, 'public');
    return key.verify(data, signature, undefined, 'hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} publicKey 
 * @return {string}
 */
function encrypt(data, publicKey) {
    var key = new NodeRSA(publicKey, 'public');
    return key.encrypt(data, 'buffer').toString('hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function decrypt(data, privateKey) {
    var key = new NodeRSA(privateKey, 'private');
    return key.decrypt(Buffer.from(data, 'hex')).toString();
}

module.exports = {
    generateKeyPair,
    sign,
    verify,
    encrypt,
    decrypt,
};
