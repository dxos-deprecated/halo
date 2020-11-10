//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import memdown from 'memdown';

import { PublicKey, PublicKeyLike, KeyPair, keyToBuffer, keyToString, sign, verify } from '@dxos/crypto';

import { KeyChain, Message, SignedMessage } from '../proto';
import { KeyRecord, RawSignature } from '../typedefs';
import { Filter, FilterFuntion } from './filter';
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

const log = debug('dxos:creds:keys'); // eslint-disable-line @typescript-eslint/no-unused-vars

const unwrapMessage = (message: any): SignedMessage => {
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
   * by the hexlified PublicKeyLike. If a single message admits more than one key, it should have a map entry for each.
   * @param publicKey
   * @param signedMessageMap
   * @param exclude Keys which should be excluded from the chain, for example, excluding FEED keys when
   * building up a chain for a DEVICE.
   */
  static buildKeyChain (publicKey: PublicKeyLike, signedMessageMap: Map<string, Message>, exclude: PublicKey[] = []): KeyChain {
    publicKey = PublicKey.from(publicKey);

    const message = unwrapMessage(signedMessageMap.get(publicKey.toHex()));
    if (!message) {
      throw Error('No such message.');
    }

    const chain: KeyChain = {
      publicKey: publicKey.asUint8Array(),
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
          chain.parents!.push(parent);
        }
      }
    }

    return chain;
  }

  /**
   * What keys were used to sign this message?
   * @param message
   * @param deep Whether to check for nested messages.
   */
  static signingKeys (message: Message | SignedMessage, deep = true): PublicKey[] {
    const all = new Set<string>();

    if (isSignedMessage(message)) {
      const { signed, signatures = [] } = message;
      for (const signature of signatures) {
        if (Keyring.validateSignature(signed, signature.signature, Buffer.from(signature.key))) {
          all.add(keyToString(signature.key));
        }
      }
    }

    if (deep) {
      for (const property of Object.getOwnPropertyNames(message)) {
        const value = (message as any)[property];
        if (typeof value === 'object') {
          const keys = Keyring.signingKeys(value, deep);
          for (const key of keys) {
            all.add(key.toHex());
          }
        }
      }
    }

    return Array.from(all).map(key => PublicKey.from(key));
  }

  /**
   * Validate all the signatures on a signed message.
   * This does not check that the keys are trusted, only that the signatures are valid.
   */
  static validateSignatures (message: Message | SignedMessage): boolean {
    message = unwrapMessage(message);
    assert(Array.isArray(message.signatures));

    const { signed, signatures } = message;

    for (const sig of signatures) {
      if (!Keyring.validateSignature(signed, sig.signature, Buffer.from(sig.key))) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validates a single signature on a message.
   * This does not check that the key is trusted, only that the signature is valid.
   */
  static validateSignature (message: any, signature: RawSignature, key: PublicKeyLike): boolean { // eslint-disable-line class-methods-use-this
    assertValidPublicKey(key);
    key = PublicKey.from(key);

    assert(typeof message === 'object' || typeof message === 'string');
    if (typeof message === 'object') {
      message = canonicalStringify(message);
      console.log(message);
    }

    const messageBuffer = Buffer.from(message);
    return verify(messageBuffer, Buffer.from(signature), key.asBuffer());
  }

  /**
   * Creates a search filter for a key that can be used for signing.
   */
  static signingFilter (attributes: Partial<KeyRecord> = {}) {
    return Filter.and(
      Filter.matches({
        ...attributes,
        own: true,
        trusted: true
      }),
      Filter.hasProperty('secretKey')
    );
  }

  private readonly _keystore: KeyStore;

  private readonly _cache = new Map<string, any>();

  /**
   * If no KeyStore is supplied, in-memory key storage will be used.
   */
  constructor (keystore?: KeyStore) {
    this._keystore = keystore || new KeyStore(memdown());
  }

  /**
   * All keys as an array.
   */
  get keys (): KeyRecord[] {
    return this.findKeys();
  }

  /**
   * Load keys from the KeyStore.  This call is required when using a persistent KeyStore.
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
   * @returns A copy of the KeyRecord, without secrets.
   */
  async addKeyRecord (keyRecord: KeyPair & Omit<KeyRecord, 'key'>) {
    assertValidKeyPair(keyRecord);

    return this._addKeyRecord(keyRecord);
  }

  /**
   * Adds the KeyRecord that must contain a publicKey but no secretKey.
   * @param {KeyRecord} keyRecord
   * @returns {KeyRecord} A copy of the KeyRecord.
   */
  async addPublicKey (keyRecord: Omit<KeyRecord, 'key' | 'secretKey'>) {
    assertValidPublicKey(keyRecord.publicKey);
    assertNoSecrets(keyRecord);

    return this._addKeyRecord(keyRecord);
  }

  /**
   * Adds a KeyRecord to the keyring and stores it in the keystore.
   * The KeyRecord may contain a key pair, or only a public key.
   * @param keyRecord
   * @param [overwrite=false] Overwrite an existing key.
   * @returns A copy of the KeyRecord, minus secrets.
   * @private
   */
  async _addKeyRecord (keyRecord: Omit<KeyRecord, 'key'>, overwrite = false) {
    const copy = checkAndNormalizeKeyRecord(keyRecord);

    if (!overwrite) {
      if (this.hasKey(copy.publicKey)) {
        throw Error('Refusing to overwrite existing key.');
      }
    }

    await this._keystore.setRecord(copy.key, copy);
    this._cache.set(copy.key, copy);

    return stripSecrets(copy);
  }

  /**
   * Adds a temporary KeyRecord to the keyring.  The key is not stored to the KeyStore.
   * The KeyRecord may contain a key pair, or only a public key.
   * @param keyRecord
   * @param [overwrite=false] Overwrite an existing key.
   * @returns A copy of the KeyRecord, minus secrets.
   * @private
   */
  _addTempKeyRecord (keyRecord: Omit<KeyRecord, 'key'>, overwrite = false) {
    const copy = checkAndNormalizeKeyRecord(keyRecord);

    if (!overwrite) {
      if (this.hasKey(copy.publicKey)) {
        throw Error('Refusing to overwrite existing key.');
      }
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
  async updateKey (keyRecord: KeyRecord) {
    assert(keyRecord);
    assertValidPublicKey(keyRecord.publicKey);

    // Do not allow updating/changing secrets.
    const cleaned = stripSecrets(keyRecord);

    const existing = this._getFullKey(cleaned.publicKey);
    const updated = { ...existing, ...cleaned };

    // There is one special case, which is not to move from a more specific to a less specific key type.
    if (existing && existing.type !== KeyType.UNKNOWN && updated.type === KeyType.UNKNOWN) {
      updated.type = existing.type;
    }

    return this._addKeyRecord(updated, true);
  }

  /**
   * Deletes the secretKey from a stored KeyRecord.
   * @param keyRecord
   * @returns {Promise<void>}
   */
  async deleteSecretKey (keyRecord: KeyRecord) {
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
   * @param keyRecord
   * @returns {boolean}
   */
  hasSecretKey (keyRecord: KeyRecord | KeyChain) {
    assert(keyRecord);
    const { publicKey } = keyRecord;
    assertValidPublicKey(publicKey);

    const existing = this._getFullKey(publicKey);
    return existing && Buffer.isBuffer(existing.secretKey);
  }

  /**
   * Is the publicKey in the keyring?
   */
  hasKey (publicKey: PublicKeyLike): boolean {
    assertValidPublicKey(publicKey);

    return !!this.getKey(publicKey);
  }

  /**
   * Tests if the given key is trusted.
   */
  isTrusted (publicKey: PublicKeyLike): boolean {
    assertValidPublicKey(publicKey);

    return this.getKey(publicKey)?.trusted ?? false;
  }

  /**
   * Return the keyRecord from the keyring, if present.
   */
  private _getFullKey (publicKey: PublicKeyLike): KeyRecord | undefined {
    assertValidPublicKey(publicKey);
    publicKey = PublicKey.from(publicKey);

    return this._findFullKey(Filter.matches({ key: publicKey.toHex() }));
  }

  /**
   * Return the keyRecord from the keyring, if present.
   * Secret key is removed from the returned version of the KeyRecord.
   *
   * @returns KeyRecord, without secretKey
   */
  getKey (publicKey: PublicKeyLike): KeyRecord | undefined {
    assertValidPublicKey(publicKey);

    const key = this._getFullKey(publicKey);
    return key ? stripSecrets(key) : undefined;
  }

  /**
   * Find all keys matching the indicated criteria: 'key', 'type', 'own', etc.
   */
  private _findFullKeys (...filters: FilterFuntion[]): KeyRecord[] {
    return Filter.filter(this._cache.values(), Filter.and(...filters));
  }

  /**
   * Find all keys matching the indicated criteria: 'key', 'type', 'own', etc.
   * Secret keys are removed from the returned version of the KeyRecords.
   * @param filters
   * @returns {KeyRecord[]} KeyRecords, without secretKeys
   */
  findKeys (...filters: FilterFuntion[]): KeyRecord[] {
    return this._findFullKeys(...filters).map(stripSecrets);
  }

  /**
   * Find one key matching the indicated criteria: 'party', 'type', etc.
   */
  private _findFullKey (...filters: FilterFuntion[]): KeyRecord | undefined {
    const matches = this._findFullKeys(...filters);
    if (matches.length > 1) {
      throw Error(`Expected <= 1 matching keys; found ${matches.length}.`);
    }
    return matches.length ? matches[0] : undefined;
  }

  /**
   * Find one key matching the indicated criteria: 'party', 'type', etc.
   * Secret key is removed from the returned version of the KeyRecord.
   * @returns KeyRecord, without secretKey
   */
  findKey (...filters: FilterFuntion[]) {
    const key = this._findFullKey(...filters);
    return key ? stripSecrets(key) : undefined;
  }

  /**
   * Serialize the Keyring contents to JSON.
   */
  toJSON () {
    const keys = this._findFullKeys().map((key) => {
      const copy = { ...key } as any;
      if (copy.publicKey) {
        copy.publicKey = keyToString(copy.publicKey);
      }
      if (copy.secretKey) {
        copy.secretKey = keyToString(copy.secretKey);
      }

      return copy;
    });

    return canonicalStringify({
      __type_url: 'dxos.credentials.keys.Keyring',
      keys
    });
  }

  /**
   * Load keys from supplied JSON into the Keyring.
   * @param {string} value
   */
  async loadJSON (value: string) {
    const parsed = JSON.parse(value);

    return Promise.all(parsed.keys.map((item: any) => {
      if (item.publicKey) {
        item.publicKey = keyToBuffer(item.publicKey);
      }
      if (item.secretKey) {
        item.secretKey = keyToBuffer(item.secretKey);
      }

      if (item.secretKey) {
        return this.addKeyRecord(item);
      } else {
        return this.addPublicKey(item);
      }
    }));
  }

  /**
   * Creates a new public/private key pair and stores in a new KeyRecord with the supplied attributes.
   * Secret key is removed from the returned version of the KeyRecord.
   * @param {Object} attributes - see KeyRecord definition for valid attributes.
   * @return {Promise<KeyRecord>} New KeyRecord, without secretKey
   */
  async createKeyRecord (attributes = {}): Promise<KeyRecord> {
    assert(arguments.length <= 1);
    const keyRecord = createKeyRecord(attributes);
    await this.addKeyRecord(keyRecord as KeyRecord & KeyPair);
    return stripSecrets(keyRecord);
  }

  /**
   * Sign the message with the indicated key or keys. The returned signed object will be of the form:
   * {
   *   signed: { ... }, // The message as signed, including timestamp and nonce.
   *   signatures: []   // An array with signature and publicKey of each signing key.
   * }
   */
  sign (message: any, keys: (KeyRecord|KeyChain)[], nonce?: Buffer, created?: string) {
    assert(typeof message === 'object');
    assert(keys);
    assert(Array.isArray(keys));

    const chains = new Map();
    const fullKeys: KeyRecord[] = [];
    keys.forEach((key) => {
      const fullKey = this._getFullKey(key.publicKey);
      assert(fullKey);
      assertValidKeyPair(fullKey);
      fullKeys.push(fullKey);
      if (isKeyChain(key)) {
        chains.set(fullKey.key, key);
      }
    });

    return signMessage(message, fullKeys, chains, nonce, created);
  }

  /**
   * Sign the data with the indicated key and return the signature.
   * KeyChains are not supported.
   */
  rawSign (data: Buffer, keyRecord: KeyRecord) {
    assert(Buffer.isBuffer(data));
    assert(keyRecord);
    assertValidPublicKey(keyRecord.publicKey);
    assertNoSecrets(keyRecord);

    const fullKey = this._getFullKey(keyRecord.publicKey) as KeyRecord;
    assertValidKeyPair(fullKey);

    return sign(data, fullKey.secretKey);
  }

  /**
   * Verify all the signatures on a signed message.
   * By default, at least ONE of the signing keys must be a known, trusted key.
   * If `requireAllKeysBeTrusted` is true, ALL keys must be known and trusted.
   * @param {SignedMessage} message
   * @param {object} options
   * @returns {boolean}
   */
  verify (message: SignedMessage, { requireAllKeysBeTrusted = false, allowKeyChains = true } = {}) {
    assert(typeof message === 'object');
    assert(message.signed);
    assert(Array.isArray(message.signatures));

    if (!Keyring.validateSignatures(message)) {
      return false;
    }

    let trustedSignatures = 0;
    const { signatures } = message;
    for (const signatureInformation of signatures) {
      const { key, keyChain } = signatureInformation;

      const keyRecord = this.getKey(Buffer.from(key));
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
  findTrusted (chain: KeyChain) {
    // `messages` contains internal state, and should not be passed in from outside.
    const walkChain = (chain: KeyChain, messages: SignedMessage[] = []): KeyRecord | undefined => {
      // Check that the signatures are valid.
      if (!Keyring.validateSignatures(chain.message)) {
        throw new Error('Invalid signature.');
      }

      // Check that the message is truly signed by the indicated key.
      if (!Keyring.signingKeys(chain.message).find(key => key.equals(chain.publicKey))) {
        throw new Error('Message not signed by indicated key.');
      }

      const key = this.getKey(Buffer.from(chain.publicKey));
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
          tmpKeys._addTempKeyRecord(key);

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
                const tmpKey = createKeyRecord({}, { publicKey: key.asBuffer() });
                tmpKeys._addTempKeyRecord(tmpKey);
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
