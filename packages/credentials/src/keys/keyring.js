//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import memdown from 'memdown';

import { keyToBuffer, keyToString, verify } from '@dxos/crypto';

import { Filter } from './filter';
import {
  canonicalStringify,
  createKeyRecord,
  assertNoSecrets,
  assertValidKeyPair,
  assertValidPublicKey,
  signMessage,
  stripSecrets,
  isKeyChain,
  checkAndNormalizeKeyRecord, isSignedMessage
} from './keyring-helpers';
import { KeyStore } from './keystore';
import { KeyType } from './keytype';

const log = debug('dxos:creds:keys'); // eslint-disable-line no-unused-vars

const unwrapMessage = (message) => {
  if (message && message.payload && !message.signed && !Array.isArray(message.signatures)) {
    return message.payload;
  }
  return message;
};

/**
 * A class for generating and managing keys, signing and verifying messages with them.
 * NOTE: This implements a write-through cache.
 */
export class Keyring {
  /**
   * Builds up a KeyChain for `publicKey` from the supplied SignedMessages. The message map should be indexed
   * by the hexlified PublicKey. If a single message admits more than one key, it should have a map entry for each.
   * @param {PublicKey} publicKey
   * @param {Map<string, Message>} signedMessageMap
   * @param {Buffer[]} [exclude] Keys which should be excluded from the chain, for example, excluding FEED keys when
   * building up a chain for a DEVICE.
   * @returns {KeyChain}
   */
  static buildKeyChain (publicKey, signedMessageMap, exclude = []) {
    const message = unwrapMessage(signedMessageMap.get(keyToString(publicKey)));
    if (!message) {
      throw Error('No such message.');
    }

    const chain = {
      publicKey,
      message,
      parents: []
    };

    if (!Keyring.validateSignatures(message)) {
      throw new Error('Invalid signature.');
    }

    const signedBy = Keyring.signingKeys(message);
    if (!signedBy.find(key => key.equals(publicKey))) {
      throw Error('Message not signed by expected key.');
    }

    for (const signer of signedBy) {
      if (!signer.equals(publicKey) && !exclude.find(key => key.equals(signer))) {
        const parent = Keyring.buildKeyChain(signer, signedMessageMap, [...signedBy, ...exclude]);
        if (parent) {
          chain.parents.push(parent);
        }
      }
    }

    return chain;
  }

  /**
   * What keys were used to sign this message?
   * @param {SignedMessage} message
   * @param {boolean} [deep=true] Whether to check for nested messages.
   * @returns {PublicKey[]}
   */
  static signingKeys (message, deep = true) {
    const all = new Set();

    if (isSignedMessage(message)) {
      const { signed, signatures } = message;
      for (const signature of signatures) {
        if (Keyring.validateSignature(signed, signature.signature, signature.key)) {
          all.add(keyToString(signature.key));
        }
      }
    }

    if (deep) {
      for (const property of Object.getOwnPropertyNames(message)) {
        const value = message[property];
        if (typeof value === 'object') {
          const keys = Keyring.signingKeys(value, deep);
          for (const key of keys) {
            all.add(keyToString(key));
          }
        }
      }
    }

    return Array.from(all).map(key => keyToBuffer(key));
  }

  /**
   * Validate all the signatures on a signed message.
   * This does not check that the keys are trusted, only that the signatures are valid.
   * @param message
   * @returns {boolean}
   */
  static validateSignatures (message) {
    assert(typeof message === 'object');
    message = unwrapMessage(message);
    assert(message.signed);
    assert(Array.isArray(message.signatures));

    const { signed, signatures } = message;

    for (const sig of signatures) {
      if (!Keyring.validateSignature(signed, sig.signature, sig.key)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validates a single signature on a message.
   * This does not check that the key is trusted, only that the signature is valid.
   * @param message
   * @param signature
   * @param {PublicKey} key
   * @returns {boolean}
   */
  static validateSignature (message, signature, key) { // eslint-disable-line class-methods-use-this
    assert(typeof message === 'object' || typeof message === 'string');
    if (typeof message === 'object') {
      message = canonicalStringify(message);
    }

    const messageBuffer = Buffer.from(message);
    return verify(messageBuffer, signature, key);
  }

  /**
   * Creates a search filter for a key that can be used for signing.
   * @param attributes
   * @return {function(*=): boolean}
   */
  static signingFilter (attributes = {}) {
    return Filter.and(Filter.matches({
      ...attributes,
      own: true,
      trusted: true
    }),
    Filter.hasProperty('secretKey'));
  }

  /**
   * If no KeyStore is supplied, in-memory key storage will be used.
   * @param [keystore]
   */
  constructor (keystore) {
    this._keystore = keystore || new KeyStore(memdown());
    this._cache = new Map();
  }

  /**
   * All keys as an array.
   * @returns {KeyRecord[]}
   */
  get keys () {
    return this.findKeys();
  }

  /**
   * Load keys from the KeyStore.  This call is required when using a persistent KeyStore.
   * @returns {Promise<Keyring>}
   */
  async load () {
    const entries = await this._keystore.getRecordsWithKey();
    for (const entry of entries) {
      const [key, value] = entry;
      this._cache.set(key, value);
    }

    return this;
  }

  /**
   * Delete every keyRecord. Safe to continue to use the object.
   */
  async deleteAllKeyRecords () {
    this._cache.clear();
    const allKeys = await this._keystore.getKeys();
    const promises = [];
    for (const key of allKeys) {
      promises.push(this._keystore.deleteRecord(key));
    }
    // TODO(burdon): Is this how we do this?
    await Promise.all(promises);
  }

  /**
   * Adds a keyRecord that must contain a key pair (publicKey/secretKey).
   * @param {KeyRecord} keyRecord
   * @returns {KeyRecord} A copy of the KeyRecord, without secrets.
   */
  async addKeyRecord (keyRecord) {
    assertValidKeyPair(keyRecord);

    return this._addKeyRecord(keyRecord);
  }

  /**
   * Adds the KeyRecord that must contain a publicKey but no secretKey.
   * @param {KeyRecord} keyRecord
   * @returns {KeyRecord} A copy of the KeyRecord.
   */
  async addPublicKey (keyRecord) {
    assertValidPublicKey(keyRecord.publicKey);
    assertNoSecrets(keyRecord);

    return this._addKeyRecord(keyRecord);
  }

  /**
   * Adds a KeyRecord to the keyring and stores it in the keystore.
   * The KeyRecord may contain a key pair, or only a public key.
   * @param {KeyRecord} keyRecord
   * @param {boolean} [overwrite=false] Overwrite an existing key.
   * @param {boolean} [temporary=false] A temporary key is not persisted to storage.
   * @returns {KeyRecord} A copy of the KeyRecord, minus secrets.
   * @private
   */
  async _addKeyRecord (keyRecord, overwrite = false, temporary = false) {
    const copy = checkAndNormalizeKeyRecord(keyRecord);

    if (!overwrite) {
      if (this.hasKey(copy.publicKey)) {
        throw Error('Refusing to overwrite existing key.');
      }
    }

    if (!temporary) {
      await this._keystore.setRecord(copy.key, copy);
    }
    this._cache.set(copy.key, copy);

    return stripSecrets(copy);
  }

  /**
   * Adds or updates a KeyRecord. The KeyRecord must contain a publicKey and it may contain a secretKey.
   * If the KeyRecord already exists, the secretKey will NOT be updated.
   * @param {KeyRecord} keyRecord
   * @returns {KeyRecord} A copy of the KeyRecord, without secrets.
   */
  async updateKey (keyRecord) {
    assert(keyRecord);
    assertValidPublicKey(keyRecord.publicKey);

    // Do not allow updating/changing secrets.
    const { secretKey, seedPhrase, ...cleaned } = keyRecord;

    const existing = this._getFullKey(cleaned.publicKey) || {};
    const updated = { ...existing, ...cleaned };

    // There is one special case, which is not to move from a more specific to a less specific key type.
    if (existing.type && existing.type !== KeyType.UNKNOWN && updated.type === KeyType.UNKNOWN) {
      updated.type = existing.type;
    }

    return this._addKeyRecord(updated, true);
  }

  /**
   * Deletes the secretKey from a stored KeyRecord.
   * @param {KeyRecord} keyRecord
   * @returns {Promise<void>}
   */
  async deleteSecretKey (keyRecord) {
    assert(keyRecord);
    assertValidPublicKey(keyRecord.publicKey);

    const existing = this._getFullKey(keyRecord.publicKey);
    if (existing) {
      const cleaned = stripSecrets(existing);
      await this._keystore.setRecord(cleaned.key, cleaned);
      this._cache.set(cleaned.key, cleaned);
    }
  }

  /**
   * Returns true if the stored KeyRecord has a secretKey available.
   * @param {KeyRecord} keyRecord
   * @returns {boolean}
   */
  hasSecretKey (keyRecord) {
    assert(keyRecord);
    assertValidPublicKey(keyRecord.publicKey);

    const existing = this._getFullKey(keyRecord.publicKey);
    return existing && Buffer.isBuffer(existing.secretKey);
  }

  /**
   * Is the publicKey in the keyring?
   * @param {PublicKey} publicKey
   * @returns {boolean}
   */
  hasKey (publicKey) {
    assertValidPublicKey(publicKey);

    return !!this.getKey(publicKey);
  }

  /**
   * Tests if the given key is trusted.
   * @param publicKey
   * @returns {boolean}
   */
  isTrusted (publicKey) {
    assertValidPublicKey(publicKey);

    const { trusted = false } = this.getKey(publicKey) || {};
    return trusted;
  }

  /**
   * Return the keyRecord from the keyring, if present.
   * @param {PublicKey} publicKey
   * @returns {KeyRecord}
   */
  _getFullKey (publicKey) {
    assertValidPublicKey(publicKey);

    const key = keyToString(publicKey);
    return this._findFullKey(Filter.matches({ key }));
  }

  /**
   * Return the keyRecord from the keyring, if present.
   * Secret key is removed from the returned version of the KeyRecord.
   * @param {PublicKey} publicKey
   * @returns {KeyRecord} KeyRecord, without secretKey
   */
  getKey (publicKey) {
    assertValidPublicKey(publicKey);

    const key = this._getFullKey(publicKey);
    return key ? stripSecrets(key) : undefined;
  }

  /**
   * Find all keys matching the indicated criteria: 'key', 'type', 'own', etc.
   * @param filters
   * @returns {KeyRecord[]}
   */
  _findFullKeys (...filters) {
    return Filter.filter(this._cache.values(), Filter.and(...filters));
  }

  /**
   * Find all keys matching the indicated criteria: 'key', 'type', 'own', etc.
   * Secret keys are removed from the returned version of the KeyRecords.
   * @param filters
   * @returns {KeyRecord[]} KeyRecords, without secretKeys
   */
  findKeys (...filters) {
    return this._findFullKeys(...filters).map(stripSecrets);
  }

  /**
   * Find one key matching the indicated criteria: 'party', 'type', etc.
   * @param {Filter[]} filters
   * @returns {KeyRecord}
   */
  _findFullKey (...filters) {
    const matches = this._findFullKeys(...filters);
    if (matches.length > 1) {
      throw Error(`Expected <= 1 matching keys; found ${matches.length}.`);
    }
    return matches.length ? matches[0] : undefined;
  }

  /**
   * Find one key matching the indicated criteria: 'party', 'type', etc.
   * Secret key is removed from the returned version of the KeyRecord.
   * @param {Filter[]} filters
   * @returns {KeyRecord} KeyRecord, without secretKey
   */
  findKey (...filters) {
    const key = this._findFullKey(...filters);
    return key ? stripSecrets(key) : undefined;
  }

  /**
   * Serialize the Keyring contents to JSON.
   * @returns {string}
   */
  toJSON () {
    const keys = this._findFullKeys().map((key) => {
      const copy = { ...key };
      if (copy.publicKey) {
        copy.publicKey = keyToString(copy.publicKey);
      }
      if (copy.secretKey) {
        copy.secretKey = keyToString(copy.secretKey);
      }

      return copy;
    });

    return canonicalStringify({
      __type_url: 'dxos.halo.credentials.keys.Keyring',
      keys
    });
  }

  /**
   * Load keys from supplied JSON into the Keyring.
   * @param {string} value
   */
  async loadJSON (value) {
    assert(typeof value === 'string');

    const promises = [];
    const parsed = JSON.parse(value);

    parsed.keys.forEach((item) => {
      if (item.publicKey) {
        item.publicKey = keyToBuffer(item.publicKey);
      }
      if (item.secretKey) {
        item.secretKey = keyToBuffer(item.secretKey);
      }

      if (item.secretKey) {
        promises.push(this.addKeyRecord(item));
      } else {
        promises.push(this.addPublicKey(item));
      }
    });

    return Promise.all(promises);
  }

  /**
   * Creates a new public/private key pair and stores in a new KeyRecord with the supplied attributes.
   * Secret key is removed from the returned version of the KeyRecord.
   * @param {Object} attributes - see KeyRecord definition for valid attributes.
   * @return {Promise<KeyRecord>} New KeyRecord, without secretKey
   */
  async createKeyRecord (attributes = {}) {
    assert(arguments.length <= 1);
    const keyRecord = createKeyRecord(attributes);
    await this.addKeyRecord(keyRecord);
    return stripSecrets(keyRecord);
  }

  /**
   * Sign the message with the indicated key or keys. The returned signed object will be of the form:
   * {
   *   signed: { ... }, // The message as signed, including timestamp and nonce.
   *   signatures: []   // An array with signature and publicKey of each signing key.
   * }
   * @param {Object} message
   * @param {(KeyRecord|KeyChain)[]} keys
   * @param {Buffer} [nonce]
   * @param {string} [created]
   * @returns {{ signed, signatures }}
   */
  sign (message, keys, nonce, created) {
    assert(typeof message === 'object');
    assert(keys);
    assert(Array.isArray(keys));
    for (const key of keys) {
      assertNoSecrets(key);
    }

    const chains = new Map();
    const fullKeys = [];
    keys.forEach((key) => {
      const fullKey = this._getFullKey(key.publicKey);
      assertValidKeyPair(fullKey);
      fullKeys.push(fullKey);
      if (isKeyChain(key)) {
        chains.set(fullKey.key, key);
      }
    });

    return signMessage(message, fullKeys, chains, nonce, created);
  }

  /**
   * Verify all the signatures on a signed message.
   * By default, at least ONE of the signing keys must be a known, trusted key.
   * If `requireAllKeysBeTrusted` is true, ALL keys must be known and trusted.
   * @param {SignedMessage} message
   * @param {object} options
   * @returns {boolean}
   */
  verify (message, options = {}) {
    assert(typeof message === 'object');
    assert(message.signed);
    assert(Array.isArray(message.signatures));

    if (!Keyring.validateSignatures(message)) {
      return false;
    }

    const { requireAllKeysBeTrusted = false, allowKeyChains = true } = options;

    let trustedSignatures = 0;
    const { signatures } = message;
    for (const signatureInformation of signatures) {
      const { key, keyChain } = signatureInformation;

      const keyRecord = this.getKey(key);
      if (keyRecord && keyRecord.trusted) {
        // The simple case is that we already trust this key.
        trustedSignatures++;
      } else if (allowKeyChains && keyChain) {
        // The more complicated case is that we trust a key in its certification chain.
        const trustedKey = this.findTrusted(keyChain);
        if (trustedKey) {
          trustedSignatures++;
        }
      }
    }

    return requireAllKeysBeTrusted ? trustedSignatures === signatures.length : trustedSignatures >= 1;
  }

  /**
   * Find the first trusted key in the KeyChain, working from tip to root. For example, if the KeyChain has
   * keys: D->C->B->A and the Keyring trusted D, that would be returned. But if it did not trust D, but did trust
   * C, then C would, and so forth back to the root (A).
   * @param {KeyChain} chain
   * @return {Promise<KeyRecord>}
   */
  findTrusted (chain) {
    // `messages` contains internal state, and should not be passed in from outside.
    const walkChain = (chain, messages = []) => {
      // Check that the signatures are valid.
      if (!Keyring.validateSignatures(chain.message)) {
        throw new Error('Invalid signature.');
      }

      // Check that the message is truly signed by the indicated key.
      if (!Keyring.signingKeys(chain.message).find(key => key.equals(chain.publicKey))) {
        throw new Error('Message not signed by indicated key.');
      }

      const key = this.getKey(chain.publicKey);
      messages.push(chain.message);

      // Do we have the key?
      if (key) {
        // If we do, but don't trust it, that is very bad.
        if (!key.trusted) {
          throw new Error('Untrusted key found in chain.');
        }
        // At this point, we should be able to verify the message with our true keyring.
        if (this.verify(chain.message)) {
          // If the key is directly trusted, then we are done.
          if (messages.length === 1) {
            return key;
          }

          // Otherwise we need to make sure the messages form a valid hierarchy, starting from the trusted key.
          messages.reverse();
          const tmpKeys = new Keyring();
          tmpKeys._addKeyRecord(key, false, true);

          // Starting from the message containing the trusted key, add the signing keys and walk forward
          // until we reach the end.
          for (const message of messages) {
            // Verification will fail if the message is not signed by an already trusted key.
            const verified = tmpKeys.verify(message);
            if (!verified) {
              throw new Error('Unable to verify message in chain');
            }

            // Add the signing keys to the trust.
            // TODO(telackey): Filter by those keys actually in the hierarchy.
            for (const key of Keyring.signingKeys(message)) {
              if (!tmpKeys.hasKey(key)) {
                tmpKeys._addKeyRecord({ publicKey: key }, false, true);
              }
            }
          }

          // If all of the above checks out, we have the right key.
          return key;
        }
        throw new Error('Unable to verify message, though key is trusted.');
      } else if (Array.isArray(chain.parents)) {
        for (const parent of chain.parents) {
          const trusted = walkChain(parent, messages);
          if (trusted) {
            return trusted;
          }
        }
      }

      return undefined;
    };

    return walkChain(chain);
  }
}
