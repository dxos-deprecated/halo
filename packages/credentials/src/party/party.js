//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';

import { discoveryKey, keyToString } from '@dxos/crypto';

import { isIdentityMessage } from '../identity/identity-message';
import { IdentityMessageProcessor } from '../identity/identity-message-processor';
import { KeyType, Keyring, keyTypeName } from '../keys';
import { PartyCredential } from '../proto';
import { isEnvelope, isPartyInvitationMessage } from './party-credential';
import { PartyInvitationManager } from './party-invitation-manager';

const log = debug('dxos:creds:party');

// TODO(telackey): Look into package specific error types.

/**
 * The party state is constructed via signed messages on the feeds.
 *
 * @event Party#'admit:key' fires on a new entity key admitted
 * @type {KeyRecord}
 *
 * @event Party#'update:key' fires when an existing entity key has attributes updated (eg, when 'hint' status is removed)
 * @type {KeyRecord}
 *
 * @event Party#'admit:feed' fires on a new feed key admitted
 * @type {KeyRecord}
 *
 * @event Party#'update:identityinfo' fires when IdentityInfo is added or updated.
 * @type {PublicKey}
 */
export class Party extends EventEmitter {
  static declaredEvents = ['admit:key', 'admit:feed', 'update:key', ...IdentityMessageProcessor.declaredEvents];

  /**
   * Initialize with party public key
   * @param {PublicKey} publicKey
   * @return {Party}
   */
  constructor (publicKey) {
    super();

    assert(Buffer.isBuffer(publicKey));

    this._publicKey = publicKey;
    this._keyring = new Keyring();
    this._invitationManager = new PartyInvitationManager(this);
    this._identityMessageProcessor = new IdentityMessageProcessor(this);

    // TODO(telackey): Switch to Buffer-aware maps.
    /** @type {Map<string, SignedMessage>} */
    this._credentialMessages = new Map();

    /** @type {Map<string, PublicKey>} */
    this._memberKeys = new Map();
    /** @type {Map<string, PublicKey>} */
    this._memberFeeds = new Map();
    /** @type {Map<string, PublicKey>} */
    this._admittedBy = new Map();

    // The Keyring must contain the Party key itself.
    this._readyToProcess = this._keyring.addPublicKey({
      publicKey,
      type: KeyType.PARTY,
      own: false
    });

    // Surface IdentityMessageProcessor events.
    for (const eventName of IdentityMessageProcessor.declaredEvents) {
      this._identityMessageProcessor.on(eventName, (...args) => this.emit(eventName, ...args));
    }
  }

  /**
   * The Party's public key.
   * @returns {PublicKey}
   */
  get publicKey () {
    return this._publicKey;
  }

  /**
   * The Party's discovery key.
   * @returns {PublicKey}
   */
  get discoveryKey () {
    return discoveryKey(this.publicKey);
  }

  /**
   * The Party's topic (hexified public key).
   * @return {string} topic for this party
   */
  get topic () {
    return keyToString(this._publicKey);
  }

  /**
   * @return {Buffer[]} of public keys for the feeds admitted to the Party.
   */
  get memberFeeds () {
    return Array.from(this._memberFeeds.values()).filter(key => this._keyring.isTrusted(key));
  }

  /**
   * @return {Buffer[]} of public keys admitted to the Party.
   */
  get memberKeys () {
    return Array.from(this._memberKeys.values()).filter(key => this._keyring.isTrusted(key));
  }

  /**
   * Returns a map of the credential messages used to construct the Party membership, indexed by the key admitted.
   * This is necessary information for demonstrating the trust relationship between keys.
   * @returns {Map<string, Message>}
   */
  get credentialMessages () {
    return this._credentialMessages;
  }

  /**
   * Returns a map of SignedMessages used to describe keys. In many cases the contents are enough (see: getInfo)
   * but the original message is needed for copying into a new Party, as when an IdentityInfo message is copied
   * from the HALO Party to a Party that is being joined.
   * @return {Map<string, Message>}
   */
  get infoMessages () {
    return this._identityMessageProcessor.infoMessages;
  }

  /**
   * Retrieve an PartyInvitation by its ID.
   * @param {Buffer} invitationID
   * @return {SignedMessage}
   */
  getInvitation (invitationID) {
    assert(invitationID);

    return this._invitationManager.getInvitation(invitationID);
  }

  /**
   * What member admitted the specified feed or member key?
   * @param {PublicKey} publicKey
   * @returns {PublicKey|undefined}
   */
  getAdmittedBy (publicKey) {
    assert(Buffer.isBuffer(publicKey));

    return this._admittedBy.get(keyToString(publicKey));
  }

  /**
   * Get info for the specified key (if available).
   * @param {Buffer} publicKey
   * @return {IdentityInfo | DeviceInfo | undefined}
   */
  getInfo (publicKey) {
    assert(Buffer.isBuffer(publicKey));

    return this._identityMessageProcessor.getInfo(publicKey);
  }

  /**
   * Lookup the PublicKey for the Party member associated with this KeyChain.
   * @param {KeyChain} chain
   * @return {Promise<PublicKey>}
   */
  findMemberKeyFromChain (chain) {
    assert(chain);

    const trustedKey = this._keyring.findTrusted(chain);
    return trustedKey && this.isMemberKey(trustedKey.publicKey) ? trustedKey.publicKey : undefined;
  }

  /**
   * Is the indicated key a trusted key associated with this party.
   * @param {PublicKey} publicKey
   * @returns {boolean}
   */
  isMemberKey (publicKey) {
    if (!publicKey) {
      return false;
    }

    return this._memberKeys.has(keyToString(publicKey)) && this._keyring.isTrusted(publicKey);
  }

  /**
   * Is the indicated key a trusted feed associated with this party.
   * @param {PublicKey} feedKey
   * @returns {boolean}
   */
  isMemberFeed (feedKey) {
    if (!feedKey) {
      return false;
    }

    return this._memberFeeds.has(keyToString(feedKey)) && this._keyring.isTrusted(feedKey);
  }

  /**
   * Process an ordered array of messages, for compatibility with Model.processMessages().
   * @param {Message[]} messages
   */
  async processMessages (messages) {
    assert(Array.isArray(messages));

    for await (const message of messages) {
      await this._processMessage(message.payload);
    }
  }

  /**
   * Receive hints for keys and feeds.
   * See `proto/greet.proto` for details on the purpose and use of hints.
   * @param {KeyHint[]} hints
   * @returns {void}
   */
  async takeHints (hints = []) {
    assert(Array.isArray(hints));

    for await (const hint of hints) {
      const { publicKey, type } = hint;
      if (!this._keyring.hasKey(publicKey)) {
        const keyRecord = await this._admitKey(publicKey, { hint: true, type });
        if (KeyType.FEED === type) {
          this.emit('admit:feed', keyRecord);
        } else {
          this.emit('admit:key', keyRecord);
        }
      }
    }
  }

  /**
   * Verifies the ENVELOPE message signature and extracts the inner message.
   * @param {SignedMessage} message
   * @return {SignedMessage}
   * @private
   */
  _unpackEnvelope (message) {
    let depth = 0;
    while (isEnvelope(message)) {
      // Verify the outer message is signed with a known, trusted key.
      this._verifyMessage(message, depth === 0);
      message = message.signed.payload.envelope.message.payload;
      depth++;
    }

    const { type } = message.signed.payload;
    const innerSignedBy = Keyring.signingKeys(message);
    switch (type) {
      case PartyCredential.Type.KEY_ADMIT: {
        const { admitKey } = message.signed.payload.keyAdmit;
        assert(admitKey);
        assert(innerSignedBy.length >= 1);
        assert(innerSignedBy.find(key => key.equals(admitKey)));
        break;
      }
      case PartyCredential.Type.FEED_ADMIT: {
        const { feedKey } = message.signed.payload.feedAdmit;
        assert(feedKey);
        assert(innerSignedBy.length >= 1);
        assert(innerSignedBy.find(key => key.equals(feedKey)));
        break;
      }
      case PartyCredential.Type.ENVELOPE:
        break;
      default:
        throw new Error(`${type} not allowed in ENVELOPE`);
    }

    return message;
  }

  /**
   * Process a Party message.
   * @param {SignedMessage} message
   * @returns {void}
   */
  async _processMessage (message) {
    await this._readyToProcess;

    // All PartyInvitation messages are handled by the PartyInvitationManager.
    if (isPartyInvitationMessage(message)) {
      return this._invitationManager.recordInvitation(message);
    }

    if (isIdentityMessage(message)) {
      return this._identityMessageProcessor.processMessage(message);
    }

    return this._processCredentialMessage(message);
  }

  /**
   * Process a replicated Party credential message, admitting keys or feeds to the Party.
   * @param {SignedMessage} message
   * @returns {void}
   */
  async _processCredentialMessage (message) {
    assert(message);
    const original = message;

    if (!message.signed || !message.signed.payload ||
      !message.signatures || !Array.isArray(message.signatures)) {
      throw new Error(`Invalid message: ${JSON.stringify(message)}`);
    }

    const envelopedMessage = isEnvelope(message);
    if (envelopedMessage) {
      message = this._unpackEnvelope(message);
    }

    switch (message.signed.payload.type) {
      case PartyCredential.Type.PARTY_GENESIS: {
        const { admitKey, feedKey } = await this._processGenesisMessage(message);
        this._credentialMessages.set(admitKey.key, original);
        this._credentialMessages.set(feedKey.key, original);

        // There is no question of who is admitting on the GENESIS.
        this._admittedBy.set(admitKey.key, this._publicKey);
        this._admittedBy.set(feedKey.key, this._publicKey);

        this.emit('admit:key', admitKey);
        this.emit('admit:feed', feedKey);
        break;
      }

      case PartyCredential.Type.KEY_ADMIT: {
        const admitKey = await this._processKeyAdmitMessage(message, !envelopedMessage, !envelopedMessage);
        this._credentialMessages.set(admitKey.key, original);

        const admittedBy = this._determineAdmittingMember(admitKey.publicKey, original);
        assert(admittedBy);
        this._admittedBy.set(admitKey.key, admittedBy);
        log(`Key ${admitKey.key} admitted by ${keyToString(admittedBy)}.`);

        this.emit('admit:key', admitKey);
        break;
      }

      case PartyCredential.Type.FEED_ADMIT: {
        const feedKey = await this._processFeedAdmitMessage(message, !envelopedMessage);
        this._credentialMessages.set(feedKey.key, original);

        // This uses 'message' rather than 'original', since in a Greeting/Envelope case we want to record the
        // feed's actual owner, not the Greeter writing the message on their behalf.
        const admittedBy = this._determineAdmittingMember(feedKey.publicKey, message);
        assert(admittedBy);
        this._admittedBy.set(feedKey.key, admittedBy);
        log(`Feed ${feedKey.key} admitted by ${keyToString(admittedBy)}.`);

        this.emit('admit:feed', feedKey);
        break;
      }

      default:
        throw new Error(`Invalid type: ${message.signed.payload.type}`);
    }
  }

  /**
   * Processes a PartyGenesis message, the start-of-authority for the Party.
   * @param {SignedMessage} message
   * @returns {void}
   * @private
   */
  async _processGenesisMessage (message) {
    assert(message);

    if (message.signed.payload.type !== PartyCredential.Type.PARTY_GENESIS) {
      throw new Error(`Invalid type: ${message.signed.payload.type} !== PARTY_GENESIS`);
    }

    // The Genesis is the root message, so cannot require a previous key.
    this._verifyMessage(message);

    const { admitKey, admitKeyType, feedKey } = message.signed.payload.partyGenesis;

    const admitRecord = await this._admitKey(admitKey, { type: admitKeyType });
    const feedRecord = await this._admitKey(feedKey, { type: KeyType.FEED });

    return {
      admitKey: admitRecord,
      feedKey: feedRecord
    };
  }

  /**
   * Processes an AdmitKey message, admitting a single key as a member of the Party.
   * @param {SignedMessage} message
   * @param {boolean} [requireSignatureFromTrustedKey=true]
   * @param {boolean} [requirePartyMatch=true]
   * @returns {void}
   * @private
   */
  async _processKeyAdmitMessage (message, requireSignatureFromTrustedKey, requirePartyMatch) {
    assert(message);

    if (message.signed.payload.type !== PartyCredential.Type.KEY_ADMIT) {
      throw new Error(`Invalid type: ${message.signed.payload.type} !== KEY_ADMIT`);
    }

    this._verifyMessage(message, requireSignatureFromTrustedKey, requirePartyMatch);

    const { admitKey, admitKeyType } = message.signed.payload.keyAdmit;

    return this._admitKey(admitKey, { type: admitKeyType });
  }

  /**
   * Processes an AdmitFeed message, admitting a single feed to participate in the Party.
   * @param {SignedMessage} message
   * @param {boolean} [requireSignatureFromTrustedKey=true]
   * @private
   */
  async _processFeedAdmitMessage (message, requireSignatureFromTrustedKey) {
    assert(message);

    if (message.signed.payload.type !== PartyCredential.Type.FEED_ADMIT) {
      throw new Error(`Invalid type: ${message.signed.payload.type} !== FEED_ADMIT`);
    }

    this._verifyMessage(message, requireSignatureFromTrustedKey);

    const { feedKey } = message.signed.payload.feedAdmit;

    return this._admitKey(feedKey, { type: KeyType.FEED });
  }

  /**
   * Verify that the signatures on this message are present, correct, and from trusted members of this Party.
   * @param {SignedMessage} message
   * @return {boolean}
   */
  verifySignatures (message) {
    assert(message, 'message null or undefined');

    return this._keyring.verify(message);
  }

  /**
   * Verify the signatures and basic structure common to all messages.
   * By default, a signature from a known, trusted key is required. In the case of an ENVELOPE, the outer message
   * will be signed by a trusted key (the key of the Greeter), but the inner key will be self-signed. In that case
   * requireSignatureFromTrustedKey should be set to false when testing the inner message.
   * @param {SignedMessage} message
   * @param {boolean} [requireSignatureFromTrustedKey=true]
   * @param {boolean} [requirePartyMatch=true]
   * @returns {boolean}
   * @private
   */
  _verifyMessage (message, requireSignatureFromTrustedKey = true, requirePartyMatch = true) {
    assert(message);

    const { signed, signatures } = message;
    if (!signed || !signatures || !Array.isArray(signatures)) {
      throw new Error(`Invalid message: ${message}`);
    }

    const checkParty = (partyKey) => {
      if (requirePartyMatch && !partyKey.equals(this._publicKey)) {
        throw new Error(`Invalid party: ${keyToString(partyKey)}`);
      }
    };

    switch (signed.payload.type) {
      case PartyCredential.Type.PARTY_GENESIS: {
        const { partyKey, admitKey, feedKey } = message.signed.payload.partyGenesis;
        checkParty(partyKey);

        if (!admitKey || !feedKey) {
          throw new Error(`Invalid message: ${message}`);
        }

        if (!Keyring.signingKeys(message).find(k => k.equals(this._publicKey))) {
          throw new Error(`Invalid message, Genesis not signed by party key: ${message}`);
        }
        break;
      }

      case PartyCredential.Type.FEED_ADMIT: {
        const { partyKey, feedKey } = message.signed.payload.feedAdmit;
        checkParty(partyKey);

        if (!feedKey) {
          throw new Error(`Invalid message: ${message}`);
        }
        break;
      }

      case PartyCredential.Type.KEY_ADMIT: {
        const { partyKey, admitKey } = message.signed.payload.keyAdmit;
        checkParty(partyKey);

        if (!admitKey) {
          throw new Error(`Invalid message: ${message}`);
        }
        break;
      }

      case PartyCredential.Type.ENVELOPE: {
        const { partyKey } = message.signed.payload.envelope;
        if (!partyKey) {
          throw new Error(`Invalid message: ${message}`);
        }
        checkParty(partyKey);
        break;
      }

      default:
        throw new Error(`Invalid type: ${signed.payload.type}`);
    }

    const sigOk = requireSignatureFromTrustedKey
      ? this._keyring.verify(message)
      : Keyring.validateSignatures(message);
    if (!sigOk) {
      throw new Error(`Rejecting unverified message: ${message}.`);
    }
  }

  /**
   * Admit the key to the allowed list.
   * @param {PublicKey} publicKey
   * @param attributes
   * @returns {boolean} true if added, false if already present
   * @private
   */
  async _admitKey (publicKey, attributes = {}) {
    assert(publicKey);
    const keyStr = keyToString(publicKey);

    const makeRecord = () => {
      return {
        type: KeyType.UNKNOWN,
        trusted: true,
        own: false,
        ...attributes, // Let attributes clobber the defaults.
        publicKey
      };
    };

    let keyRecord = this._keyring.getKey(publicKey);
    if (!keyRecord) {
      keyRecord = await this._keyring.addPublicKey(makeRecord());
    } else if (keyRecord.hint && !attributes.hint) {
      keyRecord = await this._keyring.updateKey(makeRecord());
      this.emit('update:key', keyRecord);
    }

    if (keyRecord.type === KeyType.FEED) {
      if (!this._memberFeeds.has(keyStr)) {
        log(`Admitting feed: ${keyStr} to ${this.topic}.`);
        this._memberFeeds.set(keyStr, publicKey);
      }
    } else if (!this._memberKeys.has(keyStr)) {
      log(`Admitting ${keyTypeName(keyRecord.type)}: ${keyStr} to party: ${this.topic}.`);
      this._memberKeys.set(keyStr, publicKey);
    }

    return keyRecord;
  }

  /**
   * Determine which Party member is admitting a particular credential message.
   * @returns {undefined|PublicKey}
   * @private
   */
  _determineAdmittingMember (publicKey, message) {
    if (publicKey.equals(this._publicKey)) {
      return this._publicKey;
    }

    const signingKeys = Keyring.signingKeys(message);
    for (const key of signingKeys) {
      if (!key.equals(publicKey)) {
        if (this.isMemberKey(key)) {
          return key;
        }
      }
    }
    return undefined;
  }
}
