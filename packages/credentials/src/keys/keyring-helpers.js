//
// Copyright 2020 DXOS.org
//

//
// IMPORTANT: The contents of this file are utilities/helper functions used exclusively by Keyring.
// The functions are NOT EXPORTED outside of this package.
//

import assert from 'assert';
import stableStringify from 'json-stable-stringify';

import { createKeyPair, keyToString, randomBytes, sign } from '@dxos/crypto';

import { createDateTimeString } from '../proto/datetime';
import { KeyType } from './keytype';

/**
 * Checks for a valid publicKey Buffer.
 * @param {Buffer} key
 */
export const assertValidPublicKey = (key) => {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
};

/**
 * Checks for a valid secretKey Buffer.
 * @param {Buffer} key
 */
export const assertValidSecretKey = (key) => {
  assert(Buffer.isBuffer(key));
  assert(key.length === 64);
};

/**
 * Checks for a valid publicKey/secretKey KeyPair.
 * @param {KeyPair} keyRecord
 */
// TODO(burdon): This should only happen in tests.
export const assertValidKeyPair = (keyRecord) => {
  const { publicKey, secretKey } = keyRecord;
  assertValidPublicKey(publicKey);
  assertValidSecretKey(secretKey);
};

/**
 * Checks that the KeyRecord contains no secrets (ie, secretKey and seedPhrase).
 * @param {KeyRecord} keyRecord
 */
export const assertNoSecrets = (keyRecord) => {
  assert(keyRecord);
  assert(!keyRecord.secretKey || keyRecord.secretKey === true);
  assert(!keyRecord.seedPhrase || keyRecord.seedPhrase === true);
};

/**
 * Obscures the value of secretKey and seedPhrase with a boolean.
 * @param {KeyRecord} keyRecord
 * @return {KeyRecord}
 */
export const stripSecrets = (keyRecord) => {
  assert(keyRecord);
  const { secretKey, seedPhrase, ...stripped } = keyRecord;
  return stripped;
};

// TODO(burdon): Define protocol buffer.
const ALLOWED_FIELDS = [
  'type', 'key', 'publicKey', 'secretKey', 'hint', 'own', 'trusted', 'added', 'created'
];

/**
 * Checks that there are no unknown attributes on the KeyRecord.
 * @returns {KeyRecord}
 */
export const assertValidAttributes = (keyRecord) => {
  Object.keys(keyRecord).forEach(key => {
    assert(ALLOWED_FIELDS.find(k => k === key));
  });
};

/**
 * Create a new KeyRecord with the indicated attributes.
 * @param {Object} attributes - Valid attributes above.
 * @param {KeyPair|undefined} keyPair - If undefined then a public/private key pair will be generated.
 * @returns {KeyRecord}
 */
export const createKeyRecord = (attributes = {}, keyPair = undefined) => {
  const { publicKey, secretKey } = keyPair || createKeyPair();

  // Disallow invalid attributes.
  assertValidAttributes(attributes);

  const keyRecord = {
    type: KeyType.UNKNOWN,
    key: keyToString(publicKey),
    publicKey,
    secretKey,
    hint: false,
    own: !!secretKey,
    trusted: true,
    created: createDateTimeString(),

    // Overrides the defaults above.
    ...attributes
  };

  return keyRecord;
};

/**
 * Utility method to produce stable output for signing/verifying.
 * @param obj
 * @returns {string}
 */
export const canonicalStringify = (obj) => {
  return stableStringify(obj, {
    // The point of signing and verifying is not that the internal, private state of the objects be
    // identical, but that the public contents can be verified not to have been altered. For that reason,
    // really private fields (indicated by '__') are not included in the signature. In practice, this skips __type_url,
    // and it also gives a mechanism for attaching other attributes to an object without breaking the signature.
    replacer: (key, value) => {
      return key.toString().startsWith('__') ? undefined : value;
    }
  });
};

/**
 * Sign the message with the indicated key or keys. The returned signed object will be of the form:
 * {
 *   signed: { ... }, // The message as signed, including timestamp and nonce.
 *   signatures: []   // An array with signature and publicKey of each signing key.
 * }
 * @param {Object} message
 * @param {KeyRecord[]} keys
 * @param {Map<string, KeyChain>} [keyChainMap]
 * @param {Buffer} [nonce]
 * @param {string} [created]
 * @returns {{ signed, signatures }}
 */
export const signMessage = (message, keys, keyChainMap, nonce, created) => {
  assert(typeof message === 'object');
  assert(keys);
  assert(Array.isArray(keys));
  for (const key of keys) {
    assertValidKeyPair(key);
  }

  if (!keyChainMap) {
    keyChainMap = new Map();
  }

  // If signing a string, wrap it in an object.
  if (typeof message === 'string') {
    message = { message };
  }

  // Check every key passed is suitable for signing.
  keys.forEach(keyRecord => assertValidKeyPair(keyRecord));

  const signed = {
    created: created || createDateTimeString(),
    nonce: nonce || randomBytes(32),
    payload: message
  };

  // Sign with each key, adding to the signatures list.
  const signatures = [];
  const buffer = Buffer.from(canonicalStringify(signed));
  keys.forEach(({ publicKey, secretKey }) => {
    // TODO(burdon): Already tested above?
    assertValidSecretKey(secretKey);
    signatures.push({
      signature: sign(buffer, secretKey),
      key: publicKey,
      keyChain: keyChainMap.get(keyToString(publicKey))
    });
  });

  return {
    __type_url: 'dxos.halo.SignedMessage',
    signed,
    signatures
  };
};

/**
 * Is object `key` a KeyChain?
 * @param {object} key
 * @return {boolean}
 */
export const isKeyChain = (key = {}) => {
  return Buffer.isBuffer(key.publicKey) && key.message && key.message.signed && Array.isArray(key.message.signatures);
};

/**
 * Is object `message` a SignedMessage?
 * @param {object} message
 * @returns {boolean}
 */
export const isSignedMessage = (message = {}) => {
  if (!message || typeof message !== 'object') {
    return false;
  }
  const { signed, signatures } = message;
  return signed && signatures && Array.isArray(signatures);
};

/**
 * Checks conformity and normalizes the KeyRecord. (Used before storing, so that only well-formed records are stored.)
 * @param {KeyRecord} keyRecord
 * @return {KeyRecord} A normalized copy of keyRecord.
 */
export const checkAndNormalizeKeyRecord = (keyRecord) => {
  assert(keyRecord);
  assertValidAttributes(keyRecord);

  const { publicKey, secretKey, ...rest } = keyRecord;
  assertValidPublicKey(publicKey);
  if (secretKey) {
    assertValidSecretKey(secretKey);
  }

  const keyPair = { publicKey, secretKey };
  return createKeyRecord({
    added: createDateTimeString(),
    ...rest
  }, keyPair);
};
