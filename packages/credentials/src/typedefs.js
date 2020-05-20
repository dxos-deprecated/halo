//
// Copyright 2019 DxOS
//

/**
 * @typedef {Buffer} PublicKey
 */

/**
 * @typedef {Buffer} SecretKey
 */

/**
 * @typedef KeyChain
 * @property {PublicKey} publicKey
 * @property {Message|SignedMessage} message
 * @property {KeyChain[]} parents
 */

// TODO(burdon): Generate jsDoc for types.
/**
 * @typedef KeyRecord
 * @property {string} type         - The `KeyType` type of the key. This is often unknown for keys from other sources.
 * @property {string} key          - The public key as a hex string.
 * @property {PublicKey} publicKey    - The public key as a Buffer (required).
 * @property {SecretKey} [secretKey]  - The secret key as a Buffer (this will never be visible outside the Keyring).
 * @property {boolean} [hint]      - Is this key from a Greeting "hint"?
 * @property {boolean} [own]       - Is this our key? Usually true if `secretKey` is present,
 *                                   may be false for "inception keys" such as the Party key.
 * @property {boolean} [trusted]   - Is this key to be trusted?
 * @property {string} [added]      - An RFC-3339 date/time string for when the key was added to the Keyring.
 * @property {string} [created]    - An RFC-3339 date/time string for when the key was created.
 */

/**
 * @typedef Message
 * @property {Object} payload
 */

/**
 * @typedef Signed
 * @property {string} created
 * @property {Buffer} nonce
 * @property {object} payload
 */

/**
 * @typedef Signature
 * @property {PublicKey} key
 * @property {Buffer[]} signatures
 * @property {KeyChain} [keyChain]
 */

/**
 * @typedef SignedMessage
 * @property {Signed} signed
 * @property {Signature[]} signatures
 */

/**
 * @typedef AuthMessage
 * @params {PublicKey} partyKey
 * @params {PublicKey} identityKey
 * @params {PublicKey} deviceKey
 */

/**
 * @typedef {Object} LevelDB
 */

/**
 * @callback LevelDB_Factory
 * @param {string} topic
 * @returns {LevelDB}
 */
