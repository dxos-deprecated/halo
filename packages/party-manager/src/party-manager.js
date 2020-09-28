//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';
import miss from 'mississippi';

import { waitForEvent } from '@dxos/async';
import {
  Keyring,
  KeyType,
  Party,
  createAuthMessage,
  createEnvelopeMessage,
  createJoinedPartyMessage,
  createFeedAdmitMessage,
  createKeyAdmitMessage,
  createPartyGenesisMessage,
  createIdentityInfoMessage,
  createDeviceInfoMessage,
  createPartyInvitationMessage
} from '@dxos/credentials';
import { keyToString, keyToBuffer } from '@dxos/crypto';
import { ObjectModel } from '@dxos/echo-db';
import { ModelFactory } from '@dxos/model-factory';

import { CONTACT_TYPE, ContactManager } from './contact-manager';
import { GreetingInitiator } from './greeting-initiator';
import { GreetingResponder } from './greeting-responder';
import { IdentityManager } from './identity-manager';
import { InvitationDescriptor, InvitationDescriptorType } from './invitation-descriptor';
import { InviteType } from './invite-details';
import { PartyInfo } from './party-info';
import { PartyInvitationClaimer } from './party-invitation-claims';
import { PartyProcessor } from './party-processor';
import { partyProtocolProvider } from './party-protocol-provider';
import { waitForCondition } from './util';

const log = debug('dxos:party-manager');

// TODO(telackey): Figure out a better place to put this.
const PARTY_PROPERTIES_TYPE = 'dxos.party.PartyProperties';
const PARTY_SETTINGS_TYPE = 'dxos.halo.PartySettings';

/**
 * Flags representing the current state of a Party. Used to prevent things like double opens, double closes, etc.
 */
const PartyState = Object.freeze({
  OPEN: 'OPEN',
  OPENING: 'OPENING',
  CLOSED: 'CLOSED',
  CLOSING: 'CLOSING'
});

/**
 * @typedef SecretProvider
 */

/**
 * Drives a FeedStore such that messages received on that FeedStore's message stream
 * correspond to the messages from the open Parties. Provides access to ancillary
 * services: Identity management, Device management, Party invitation and greeting.
 *
 * @event PartyManager#'party' fires when a Party is added to the manager (whether a newly created Party, one joined
 * on another device, or one loaded from storage)
 * @type {PublicKey}
 *
 * @event PartyManager#'party:update' fires when a Party is updated (eg, a new key or feed added)
 * @type {PublicKey}
 *
 * @event PartyManager#'party:info' fires when PartyInfo is added to the manager (whether a newly created Party,
 * one joined on another device, or one loaded from storage)
 * @type {PublicKey}
 *
 * @event PartyManager#'party:info:update' fires when PartyInfo is updated
 * @type {PublicKey}
 *
 * @event PartyManager#'@package:device:info' fires when a DeviceInfo message has been processed on the Halo
 * @type {DeviceInfo}
 *
 * @event PartyManager#'@package:identity:info' fires when an IdentityInfo message has been processed on the Halo
 * @type {IdentityInfo}
 *
 * @event PartyManager#'@package:identity:joinedparty' fires when a JoinedParty message has been processed
 * @type {PublicKey}
 */
export class PartyManager extends EventEmitter {
  // The key is the hexlified PublicKey of the party.
  /** @type {Map<string, Party>} */
  _parties;

  // The key is the hexlified PublicKey of the party.
  /** @type {Map<string, PartyState>} */
  _partyState;

  // The key is the hexlified PublicKey of the party.
  /** @type {Map<string, PartyInfo>} */
  _partyInfoMap;

  /** @type {FeedStore} */
  _feedStore;

  /** @type {Keyring} */
  _keyRing;

  /** @type {NetworkManager} */
  _networkManager;

  /** @type {boolean} */
  _initialized;

  /** @type {boolean} */
  _destroyed;

  /** @type {PartyProcessor} */
  _partyProcessor;

  /** @type {ModelFactory} */
  _modelFactory;

  /** @type {Map<string, Model>} */
  _partyPropertyModels;

  /** @type {Model} */
  _partySettingsModel;

  /**
   *
   * @param {FeedStore} feedStore configured Feed Store
   * @param {Keyring} keyRing Keyring
   * @param {NetworkManager} networkManager
   */
  constructor (feedStore, keyRing, networkManager) {
    assert(feedStore);
    assert(keyRing);
    assert(networkManager);

    super();

    this._feedStore = feedStore;
    this._keyRing = keyRing;
    this._networkManager = networkManager;

    this._destroyed = false;
    this._initialized = false;
    this._parties = new Map();
    this._partyState = new Map();
    this._partyInfoMap = new Map();
    this._partyProcessor = new PartyProcessor(this, this._feedStore, this._keyRing);
    this._identityManager = new IdentityManager(this);
    this._contactManager = new ContactManager();

    this._modelFactory = new ModelFactory(this._feedStore, {
      onAppend: async (message, { topic }) => {
        const feed = await this.getWritableFeed(keyToBuffer(topic));
        return feed.append(message);
      }
    });

    this._partyPropertyModels = new Map();
  }

  /**
   * @package
   * @returns {Keyring}
   */
  get keyRing () {
    return this._keyRing;
  }

  /**
   * @return {IdentityManager}
   */
  get identityManager () {
    return this._identityManager;
  }

  /**
   * Must be called after constructor.
   * @throws {Error} TODO(dboreham): add details.
   */
  async initialize () {
    assert(!this._destroyed, 'Used after destroy.');
    assert(!this._initialized, 'Reinitialize attempt.');

    this._initialized = true;

    // Make certain that a DEVICE key is available.
    {
      const existingKey = this._keyRing.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));
      if (!existingKey) {
        await this._keyRing.createKeyRecord({ type: KeyType.DEVICE });
      }
    }

    // Echo some of the PartyProcessor events for package-level consumption (@package: prefix).
    {
      const eventNames = ['@package:device:info', '@package:identity:info', '@package:identity:joinedparty'];
      for (const eventName of eventNames) {
        this._partyProcessor.on(eventName, (...args) => this.emit(eventName, ...args));
      }
    }

    this._partyProcessor.once('@package:sync', () => {
      this._contactManager.start();
    });

    // Combine several events into a generic 'update' event.
    {
      const eventNames = ['party', 'party:update', 'party:info', 'party:info:update'];
      for (const eventName of eventNames) {
        this.on(eventName, (partyKey) => this.emit('update', partyKey));
      }
    }

    // Gather info on the Parties we already know about.
    await this._loadKnownPartyInfo();

    const hasIdentity = this._identityManager.hasIdentity();
    const hasHalo = await this._identityManager.isInitialized();

    // Check if we are in a valid state regarding our Identity key and its associated Halo in the FeedStore.
    if (hasIdentity && !hasHalo && !this._keyRing.hasSecretKey(this._identityManager.keyRecord)) {
      throw new Error('Halo uninitialized, and no Identity secret key is present to initialize it.');
    }

    // Begin reading from the FeedStore.
    await this._partyProcessor.start();

    // If we have an Halo, wait for it to be processed as part of initialization.
    if (hasHalo) {
      await this._identityManager.waitForIdentity();
    }
  }

  /**
   * Cleanup, release resources.
   */
  async destroy () {
    await this._contactManager.destroy();

    if (this._partyProcessor) {
      this._partyProcessor.removeAllListeners();
      this._partyProcessor.destroy();
      this._partyProcessor = undefined;
    }

    for await (const info of this._partyInfoMap.values()) {
      info.removeAllListeners();
    }

    for await (const party of this._parties.values()) {
      party.removeAllListeners();
      await this.closeParty(party.publicKey);
    }

    for await (const model of this._partyPropertyModels.values()) {
      await model.destroy();
    }

    await this._partySettingsModel.destroy();

    this._destroyed = true;
    this.emit('destroyed');
    this.removeAllListeners();
  }

  /**
   * Creates a Party.
   * @return {Party} The newly created Party.
   */
  async createParty () {
    this._assertValid();
    const hasHalo = await this._identityManager.isInitialized();
    assert(hasHalo, 'Halo does not exist.');

    // Make up a brand new key for the Party.
    const partyKey = await this._keyRing.createKeyRecord({ type: KeyType.PARTY });

    // TODO(telackey): We really want to admit our Identity, but we cannot rely on having
    // that secretKey available, so instead we use the Party's inception key to admit
    // our Identity by using it to sign a copy of our IdentityGenesis message.
    return this._createParty(partyKey, partyKey);
  }

  /**
   * Opens a Party. Party designated by partyKey must have previously been created or joined.
   * @param {PublicKey} partyKey Party Key
   * @throws {Error} TODO(dboreham): add details.
   */
  async openParty (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));

    const party = this.getParty(partyKey);
    if (!party) {
      throw new Error(`Unknown party: ${keyToString(partyKey)}`);
    }

    // Prevent opening while in the process of closing.
    const currentState = await waitForCondition(() => {
      const state = this._getPartyState(party);
      return state !== PartyState.CLOSING ? state : undefined;
    });

    if (currentState === PartyState.OPEN || currentState === PartyState.OPENING) {
      log(`openParty (already open or opening): ${keyToString(partyKey)}`);
      return;
    }
    this._setPartyState(party, PartyState.OPENING);

    const feed = await this.getWritableFeed(partyKey);
    const feedKey = this._keyRing.getKey(feed.key);

    let deviceKey;
    if (this.isHalo(party.publicKey)) {
      // In the Halo case, all we need is the Device's own key, so we can proceed immediately.
      deviceKey = this._identityManager.deviceManager.keyRecord;
    } else {
      // For other parties, we need the whole keychain from the Device back to the Identity, so we may need to
      // wait for that to become available if the relevant messages have not already been processed.
      await this._identityManager.waitForIdentity();
      deviceKey = this._identityManager.deviceManager.keyChain;
    }

    const credentials = createAuthMessage(
      this._keyRing,
      party.publicKey,
      this._identityManager.keyRecord,
      deviceKey,
      feedKey
    );

    await this._networkManager.joinProtocolSwarm(party.publicKey,
      partyProtocolProvider(
        this._identityManager.deviceManager.publicKey,
        credentials,
        party,
        this
      ));

    this._setPartyState(party, PartyState.OPEN);
  }

  /**
   * Close a party. Silently succeeds if not open to prevent caller needing to synchronize. No return value.
   * @param {PublicKey} partyKey
   */
  async closeParty (partyKey) {
    this._assertValid();

    const party = this.getParty(partyKey);
    assert(party);

    // Prevent closing while in the process of opening.
    const currentState = await waitForCondition(() => {
      const state = this._getPartyState(party);
      return state !== PartyState.OPENING ? state : undefined;
    });

    if (currentState === PartyState.CLOSING || currentState === PartyState.CLOSED) {
      log(`closeParty (already closed or closing): ${keyToString(partyKey)}`);
      return;
    }

    this._setPartyState(party, PartyState.CLOSING);
    await this._networkManager.leaveProtocolSwarm(partyKey);
    this._setPartyState(party, PartyState.CLOSED);
  }

  /**
   * Issues an invitation to join a Party.
   * @param {PublicKey} partyKey
   * @param {InviteDetails} inviteDetails
   * @param {InviteOptions} [options]
   * @returns {InvitationDescriptor}
   */
  async inviteToParty (partyKey, inviteDetails, options = {}) {
    this._assertValid();
    assert(this.hasParty(partyKey));

    const party = this.getParty(partyKey);
    const { onFinish, expiration } = options;

    switch (inviteDetails.type) {
      case InviteType.INTERACTIVE: {
        const { secretValidator, secretProvider } = inviteDetails;
        const responder = new GreetingResponder(party, this, this._keyRing, this._networkManager);
        const swarmKey = await responder.start();
        const invitation = await responder.invite(secretValidator, secretProvider, onFinish, expiration);

        const logData = {
          partyKey: keyToString(partyKey),
          rendezvousKey: keyToString(swarmKey),
          invitationId: keyToString(invitation)
        };
        log(`Created invitation to party: ${JSON.stringify(logData)}`);
        return new InvitationDescriptor(InvitationDescriptorType.INTERACTIVE, swarmKey, invitation);
      }
      case InviteType.OFFLINE_KEY: {
        if (onFinish || expiration) {
          throw new Error('Invalid options, onFinish and expiration cannot be used with OFFLINE invitations.');
        }

        const { publicKey } = inviteDetails;
        const writeStream = await this.getWritableStream(party.publicKey);
        const invitationMessage = createPartyInvitationMessage(this._keyRing,
          party.publicKey,
          publicKey,
          this.identityManager.keyRecord,
          this.identityManager.deviceManager.keyChain
        );
        writeStream.write(invitationMessage);

        return new InvitationDescriptor(InvitationDescriptorType.OFFLINE_KEY, party.publicKey,
          invitationMessage.payload.signed.payload.id);
      }
      default:
        throw new Error(`Unknown InviteType: ${inviteDetails.type}`);
    }
  }

  /**
   * Join a Party by redeeming an Invitation.
   * @param {InvitationDescriptor} invitationDescriptor
   * @param {SecretProvider} secretProvider
   * @returns {Party} The now open Party.
   */
  async joinParty (invitationDescriptor, secretProvider) {
    this._assertValid();
    const originalInvitation = invitationDescriptor;

    log(`Joining party with invitation id: ${keyToString(invitationDescriptor.invitation)}`);

    if (InvitationDescriptorType.OFFLINE_KEY === invitationDescriptor.type) {
      const invitationClaimer = new PartyInvitationClaimer(invitationDescriptor, this, this._networkManager);
      await invitationClaimer.connect();
      invitationDescriptor = await invitationClaimer.claim();
      log(`Party invitation ${keyToString(originalInvitation.invitation)} triggered interactive Greeting`,
        `at ${keyToString(invitationDescriptor.invitation)}`);
      await invitationClaimer.destroy();
    }

    const initiator = new GreetingInitiator(invitationDescriptor, this, this._keyRing, this._networkManager);
    await initiator.connect();
    const party = await initiator.redeemInvitation(secretProvider);
    await initiator.destroy();

    if (!this.isHalo(party.publicKey)) {
      await this._writeIdentityInfo(party);
      await this._recordPartyJoining(party);
    }

    log(`Joined party: ${keyToString(party.publicKey)}`);

    return party;
  }

  /**
   * Set one or more properties on the specified Party as key/value pairs.
   * Expected properties include:
   *    {String} displayName
   * @param {PublicKey} partyKey
   * @param {Object} properties
   * @returns {Promise<void>}
   */
  async setPartyProperty (partyKey, properties) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));
    assert(properties);

    // Both of these are expected to exist for any properly constructed Party.
    const model = this._partyPropertyModels.get(keyToString(partyKey));
    assert(model);

    const item = this._getPartyPropertiesItem(partyKey);
    assert(item);

    model.updateItem(item.id, properties);
  }

  /**
   * Unsubscribe to a Party (this Party must already exist and have previously been joined/created).
   * @param partyKey
   * @returns {Promise<void>}
   */
  async unsubscribe (partyKey) {
    this._assertValid();

    const item = this._getPartySettingsItem(partyKey);
    assert(item);

    this._partySettingsModel.updateItem(item.id, { subscribed: false });
  }

  /**
   * Subscribe to a Party (this Party must already exist and have previously been joined/created).
   * @param partyKey
   * @returns {Promise<void>}
   */
  async subscribe (partyKey) {
    this._assertValid();

    const item = this._getPartySettingsItem(partyKey);
    assert(item);

    this._partySettingsModel.updateItem(item.id, { subscribed: true });
  }

  /**
   * Returns an open writable stream through which messages for the designated party can be published.
   * @param {PublicKey} partyKey
   * @return {stream.Writable}
   * @throws {Error} TODO(dboreham): add details.
   */
  async getWritableStream (partyKey) {
    this._assertValid();

    const feed = await this.getWritableFeed(partyKey);

    // Chunk needs to be a string or Buffer, which means it needs to be encoded first.
    const write = (chunk, enc, cb) => {
      // Do not want to take raw bytes, only objects.
      assert(!Buffer.isBuffer(chunk));
      assert(typeof chunk === 'object');
      feed.append(chunk);
      cb();
    };

    // Creates a WritableStream opened in objectMode which appends the 'chunks' (in this case, objects) to our feed.
    return miss.to.obj(write);
  }

  /**
   * Return an array of party keys.
   * When opts.openOnly == true, only return parties that are currently open.
   *
   * @typedef {Object} getPartyKeysOpts
   * @property {boolean} openOnly
   *
   * @param {getPartyKeysOpts} opts
   * @return {PublicKey[]}
   */
  getPartyKeys (opts) {
    this._assertValid();
    // eslint-disable-next-line no-unused-vars
    const { openOnly = false } = opts;
    // TODO(dboreham): implement openOnly check, verify party manager knowing about not-open parties makes sense.
    return Array.from(this._parties.values()).map(party => party.publicKey);
  }

  /**
   * Return the Party object associated with a given Party Key, or undefined if no such Party is known.
   * The party must be open. If not open, returns undefined.
   * @param {PublicKey} partyKey
   * @return {Party}
   */
  getParty (partyKey) {
    assert(Buffer.isBuffer(partyKey));
    this._assertValid();
    return this._parties.get(keyToString(partyKey));
  }

  /**
   * Get information about all Parties known to the PartyManager,
   *   primarily for diagnostic/user-facing visualization purposes.
   * @return {PartyInfo[]}
   */
  getPartyInfoList () {
    this._assertValid();
    return Array.from(this._partyInfoMap.values());
  }

  /**
   * Get information about the party associated with partyKey,
   *   primarily for diagnostic/user-facing visualization purposes.
   * @param {PublicKey} partyKey
   * @return {PartyInfo}
   */
  getPartyInfo (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));
    return this._partyInfoMap.get(keyToString(partyKey));
  }

  /**
   * Return whether or not the PartyManager has information about the Party associated with partyKey.
   * @param {PublicKey} partyKey
   * @return {boolean}
   */
  hasPartyInfo (partyKey) {
    return !!this.getPartyInfo(partyKey);
  }

  /**
   * Returns true if the specified Party is known, else false.
   * @param {PublicKey} partyKey
   * @return {boolean}
   */
  hasParty (partyKey) {
    return !!this.getParty(partyKey);
  }

  /**
   * Is the specified Party key for the Halo?
   * Only intended to be used by code in this package, not part of the public interface.
   * @package
   * @param {PublicKey} partyKey
   * @return {boolean}
   */
  isHalo (partyKey) {
    return this._identityManager.keyRecord && this._identityManager.publicKey.equals(partyKey);
  }

  /**
   * Returns an Array of all known Contacts across all Parties.
   * @returns {Contact[]}
   */
  async getContacts () {
    return this._contactManager.getContacts();
  }

  /**
   * Creates a Party and admits the initial member using the specified key pairs.
   * Waits until this node quiesces: the resulting Party object has been fully constructed.
   * @param {KeyRecord} partyKeyRecord
   * @param {KeyRecord} admitKeyRecord
   * @param {Object} props
   * TODO(telackey): Implement display name.
   * @property props.deviceDisplayName {string} When creating an Identity halo party, supplies the Device display name.
   * @return {Party}
   */
  // TODO(telackey): Move out of this file.
  async _createParty (partyKeyRecord, admitKeyRecord, props = {}) {
    this._assertValid();
    log(`Creating party: ${partyKeyRecord.key}`);

    // Add a listener for when the Party object gets created for this new Party.
    const partyProcessedWaiter = waitForEvent(this, 'party',
      eventPartyKey => eventPartyKey.equals(partyKeyRecord.publicKey));

    // Create and open a Feed for this Party, and add it to the Keyring.
    const feed = await this.initWritableFeed(partyKeyRecord.publicKey);
    const feedKey = this._keyRing.getKey(feed.key);

    const writeMessage = this._messageWriterFactory(feed);

    // Write the PARTY_GENESIS message to the feed.
    writeMessage(createPartyGenesisMessage, partyKeyRecord, feedKey, admitKeyRecord);

    if (this.isHalo(partyKeyRecord.publicKey)) {
      // 1. Write the IdentityGenesis message.
      writeMessage(createKeyAdmitMessage, this._identityManager.publicKey, this._identityManager.keyRecord);
      // 2. Write the IdentityInfo message.
      const { identityDisplayName } = props;
      writeMessage(createIdentityInfoMessage,
        identityDisplayName || keyToString(this._identityManager.keyRecord.publicKey),
        this._identityManager.keyRecord);
      // 3. Write the DeviceInfo message.
      const { deviceDisplayName } = props;
      writeMessage(createDeviceInfoMessage,
        deviceDisplayName || keyToString(this._identityManager.deviceManager.publicKey),
        this._identityManager.deviceManager.keyRecord);
      log(`Created identity halo: ${partyKeyRecord.key}`);
    } else {
      // 1. Obtain the IdentityGenesis message (we should already have it...)
      assert(this._identityManager.identityGenesisMessage);
      // 2. Copy it into feed, signed by the admitKeyRecord.
      writeMessage(createEnvelopeMessage, partyKeyRecord.publicKey,
        this._identityManager.identityGenesisMessage, admitKeyRecord);
      // 3. Write a FeedAdmit message signed by the Identity.
      writeMessage(createFeedAdmitMessage, partyKeyRecord.publicKey, feedKey,
        this._identityManager.deviceManager.keyChain);

      log(`Created party: ${partyKeyRecord.key}`);
    }

    // We are done signing with the PARTY key, so it is time to throw away its secretKey.
    await this._keyRing.deleteSecretKey(partyKeyRecord);

    // TODO(telackey): Wait also for each of the messages we wrote to be processed by the Party?
    // TODO(telackey): When is this promise rejected?
    // Return a Promise which will resolve only after the Party has been processed.
    await partyProcessedWaiter;
    const party = this.getParty(partyKeyRecord.publicKey);
    assert(party);

    if (!this.isHalo(partyKeyRecord.publicKey)) {
      // 4. If we have IdentityInfo, copy that over too.
      await this._writeIdentityInfo(party);
      // 5. Write the JoinedParty message to the Halo using the deviceKey.
      await this._recordPartyJoining(party);
      // 6. Create and write the PartyProperties item for the Party.
      await this._createPartyPropertiesItem(party);
    }

    return party;
  }

  /**
   * Returns true if a writable feed exists for the Party.
   * @param {PublicKey} partyKey
   * @return {boolean}
   * @throws {Error} TODO(dboreham): add details.
   * @package
   */
  async hasWritableFeed (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));

    const partyString = keyToString(partyKey);
    return !!this._feedStore.getDescriptors()
      .find(desc => desc.metadata.topic === partyString && desc.metadata.writable);
  }

  /**
   * Returns an open, writable feed for a new Party.
   * hasParty(partyKey) must be false, or else an error is thrown.
   * @param {PublicKey} partyKey
   * @return {Feed}
   * @throws {Error} TODO(dboreham): add details.
   * @package
   */
  async initWritableFeed (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));

    if (this.hasParty(partyKey)) {
      throw new Error(`Refusing to init writable feed for already initialized Party: ${keyToString(partyKey)}`);
    }

    return this._getWritableFeed(partyKey);
  }

  /**
   * Returns an open, writable feed for the Party.
   * hasParty(partyKey) must be true, or else an error is thrown.
   * @param {PublicKey} partyKey
   * @return {Feed}
   * @throws {Error} TODO(dboreham): add details.
   * @package
   */
  async getWritableFeed (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));

    if (!this.hasParty(partyKey)) {
      throw new Error(`Unknown party: ${keyToString(partyKey)}`);
    }

    return this._getWritableFeed(partyKey);
  }

  /**
   * Returns an open, writable feed for the Party.
   * @param {PublicKey} partyKey
   * @return {Feed}
   * @throws {Error} TODO(dboreham): add details.
   * @package
   */
  async _getWritableFeed (partyKey) {
    this._assertValid();
    assert(Buffer.isBuffer(partyKey));

    const partyString = keyToString(partyKey);

    let feed = await this._feedStore.getOpenFeed(desc => desc.metadata.topic === partyString && desc.metadata.writable);
    if (!feed) {
      feed = await this._feedStore.openFeed(`/topic/${partyString}/writable`, {
        metadata: { topic: partyString, writable: true }
      });
    }

    if (!this._keyRing.hasKey(feed.key)) {
      await this._keyRing.addKeyRecord({
        publicKey: feed.key,
        secretKey: feed.secretKey,
        type: KeyType.FEED
      });
    }

    return feed;
  }

  /**
   * Checks whether the PartyManager is in a valid state.
   */
  // TODO(telackey): Review to see if there are more tings that can be validated here now.
  _assertValid () {
    assert(!this._destroyed, 'Used after destroyed.');
    assert(this._initialized, 'Uninitialized.');
  }

  /**
   * Helper adds syntactic sugar for repeated message create, sign, write calls.
   * @param {Feed} writeFeed
   * @return {function(...[*]=)}
   */
  _messageWriterFactory (writeFeed) {
    const keyRing = this._keyRing;
    return (messageFactory, ...rest) => {
      writeFeed.append(messageFactory(keyRing, ...rest));
    };
  }

  /**
   * Package private method for loading a party initiated by halo message.
   * If writeFeedAdmitMessage is true, and the Feed is created, a signed FeedAdmit message will be written
   * to the Feed. This is needed when 'auto-opening' a Party which was joined on another Device.
   * @package
   * @param {PublicKey} partyKey
   * @param {boolean} [writeFeedAdmitMessage=false]
   * @return {Promise<Party>}
   */
  async initParty (partyKey, writeFeedAdmitMessage = false) {
    assert(!this.hasParty(partyKey));

    if (!this._keyRing.hasKey(partyKey)) {
      await this._keyRing.addPublicKey({
        publicKey: partyKey,
        type: KeyType.PARTY,
        own: false
      });
    }

    if (!this.hasPartyInfo(partyKey) && !this.isHalo(partyKey)) {
      await this._initPartyInfo(partyKey);
    }

    // First check if we already have the feed; if so, that is all that is required.
    const hadFeed = await this.hasWritableFeed(partyKey);
    const feed = await this.initWritableFeed(partyKey);

    // If the feed is new, (optionally) write a signed FeedAdmit message for it.
    if (!hadFeed && writeFeedAdmitMessage) {
      // Once we have our Device's keyChain loaded, sign the FeedAdmit message with it.
      waitForCondition(() => this._identityManager.deviceManager.keyChain).then(() => {
        // TODO(telackey): Should this be a FeedGenesis message?
        feed.append(createFeedAdmitMessage(
          this._keyRing,
          partyKey,
          this._keyRing.getKey(feed.key),
          this._identityManager.deviceManager.keyChain
        ));
      });
    }

    const party = new Party(partyKey);

    // At the least, we trust ourselves.
    // TODO(telackey): 'Hints' are normally used in Greeting. We have a similar need here, but should these
    // still be called 'hints', or something else?
    if (!this.isHalo(partyKey)) {
      await party.takeHints([
        { publicKey: this._identityManager.publicKey, type: KeyType.IDENTITY },
        { publicKey: feed.key, type: KeyType.FEED }
      ]);
    }

    // TODO(telackey): The only reason to save these keys to the main Keyring is to aid in recovery,
    // so that we can know whom to trust without requiring 'hints'. However, that is useless without
    // associating specific keys with specific Parties, something we no longer have since removing
    // the 'parties' attribute from the KeyRecords.
    const partyUpdate = async (keyRecord) => {
      const current = this._keyRing.getKey(keyRecord.publicKey);
      if (!current) {
        await this._keyRing.addPublicKey(keyRecord);
      } else if (current.hint && !keyRecord.hint) {
        await this._keyRing.updateKey(keyRecord);
      }
      this.emit('party:update', partyKey);
    };

    party.on('admit:key', partyUpdate);
    party.on('update:key', partyUpdate);
    party.on('admit:feed', partyUpdate);

    const partyStr = keyToString(partyKey);
    this._parties.set(partyStr, party);
    this.emit('party', partyKey);
    this.emit('party:update', partyKey);

    const partyPropertyModel = await this._modelFactory.createModel(ObjectModel, {
      type: PARTY_PROPERTIES_TYPE,
      topic: partyStr
    });

    partyPropertyModel.on('update', async () => {
      const partyInfo = this.getPartyInfo(partyKey);
      const item = this._getPartyPropertiesItem(partyKey);
      partyInfo.setProperties(item.properties);
    });

    this._partyPropertyModels.set(partyStr, partyPropertyModel);

    if (this.isHalo(partyKey)) {
      assert(!this._partySettingsModel);

      this._partySettingsModel = await this._modelFactory.createModel(ObjectModel, {
        type: PARTY_SETTINGS_TYPE,
        topic: partyStr
      });

      this._partySettingsModel.on('update', async (_, messages) => {
        for (const message of messages) {
          const item = this._partySettingsModel.getItem(message.objectId);
          assert(item);

          const { partyKey, ...settings } = item.properties;
          await waitForCondition(() => this.getPartyInfo(partyKey));
          const info = this.getPartyInfo(partyKey);
          info.setSettings(settings);
        }
      });

      this._contactManager.setModel(await this._modelFactory.createModel(ObjectModel, {
        type: CONTACT_TYPE,
        topic: partyStr
      }));
    }

    return party;
  }

  /**
   * Create and initialize a new PartyInfo object for the indicted partyKey.
   * @param partyKey
   * @returns {Promise<PartyInfo>}
   * @private
   */
  async _initPartyInfo (partyKey) {
    assert(!this.hasPartyInfo(partyKey));
    assert(!this.isHalo(partyKey));

    const info = new PartyInfo(partyKey, this);
    info.on('update', (member) => {
      if (member && !member.isMe) {
        this._contactManager.addContact(member);
      }
      this.emit('party:info:update', partyKey);
    });

    info.on('subscription', async () => {
      const party = this.getParty(partyKey);
      if (party) {
        if (info.subscribed && !party.isOpen()) {
          await this.openParty(partyKey);
        } else if (!info.subscribed && party.isOpen()) {
          await this.closeParty(partyKey);
        }
      }
    });

    this._partyInfoMap.set(keyToString(partyKey), info);
    this.emit('party:info', partyKey);
    return info;
  }

  /**
   * Copies the IdentityInfo message (if present) into the target Party.
   * @param {Party} party
   * @returns {Promise<void>}
   * @private
   */
  async _writeIdentityInfo (party) {
    assert(party);
    const feed = await this.getWritableFeed(party.publicKey);
    // This message is purely informational, so it doesn't need re-signed for this Party.
    if (this._identityManager.identityInfoMessage) {
      feed.append(this._identityManager.identityInfoMessage);
    }
  }

  /**
   * Creates a PartyProperty object and writes it to the Party.
   * @param {Party} party
   * @param {Object} properties
   * @returns {Promise<string>}
   * @private
   */
  async _createPartyPropertiesItem (party, properties = {}) {
    assert(party);
    const model = await this._partyPropertyModels.get(keyToString(party.publicKey));
    return model.createItem(PARTY_PROPERTIES_TYPE, properties);
  }

  /**
   * Writes the JoinedParty informational message to the Halo.
   * @param {Party} party
   * @returns {Promise<void>}
   * @private
   */
  async _recordPartyJoining (party) {
    assert(party);
    const feed = await this.getWritableFeed(party.publicKey);
    const feedKey = this._keyRing.getKey(feed.key);
    const haloFeed = await this.getWritableFeed(this._identityManager.publicKey);

    const memberKeys = party.memberKeys.map(publicKey => {
      // Since this record is used only to provide bootstrapping hints to other devices, only the
      // publicKey is required, not the other attributes (eg, type).
      return {
        publicKey
      };
    });

    const memberFeeds = party.memberFeeds.map(publicKey => {
      return {
        publicKey,
        type: KeyType.FEED
      };
    });

    haloFeed.append(createJoinedPartyMessage(
      party.publicKey,
      this._identityManager.deviceManager.publicKey,
      feedKey.publicKey,
      [...memberKeys, ...memberFeeds]
    ));

    this._partySettingsModel.createItem(PARTY_SETTINGS_TYPE, {
      partyKey: party.publicKey,
      subscribed: true
    });
  }

  /**
   * Load information about already known Parties.
   * Should only be called once, during initialize().
   * @returns {Promise<void>}
   * @private
   */
  async _loadKnownPartyInfo () {
    const descriptors = this._feedStore.getDescriptors();
    for await (const descriptor of descriptors) {
      const { topic } = descriptor;
      if (topic && !this._partyInfoMap.has(topic)) {
        const partyKey = keyToBuffer(topic);
        if (!this.isHalo(partyKey)) {
          await this._initPartyInfo(partyKey);
        }
      }
    }
  }

  /**
   * Get the PartyProperties item for the indicated Party.
   * @param {PublicKey} partyKey
   * @returns {undefined|{PartyProperties}}
   * @private
   */
  _getPartyPropertiesItem (partyKey) {
    this._assertValid();

    const model = this._partyPropertyModels.get(keyToString(partyKey));
    assert(model);

    const objects = model.getObjectsByType(PARTY_PROPERTIES_TYPE);
    if (!objects.length) {
      log(`Expected one PartyProperties item, found ${objects.length}.`);
      return undefined;
    }

    // TODO(telackey): There should only be one of these, but we will need to take steps to enforce that.
    if (objects.length > 1) {
      log(`Expected one PartyProperties item, found ${objects.length}.`);
      objects.sort((a, b) => a.id.localeCompare(b.id));
    }

    return objects[0];
  }

  /**
   * Get the PartySettings item for the indicated Party.
   * @param {PublicKey} partyKey
   * @returns {undefined|{PartySettings}}
   * @private
   */
  _getPartySettingsItem (partyKey) {
    this._assertValid();

    return this._partySettingsModel.getObjectsByType(PARTY_SETTINGS_TYPE)
      .find(item => partyKey.equals(item.properties.partyKey));
  }

  /**
   * Retrieve the PartyState of the indicated Party.
   * @param {Party} party
   * @returns {PartyState}
   * @private
   */
  _getPartyState (party) {
    this._assertValid();
    assert(party);

    return this._partyState.get(keyToString(party.publicKey)) || PartyState.CLOSED;
  }

  /**
   * Set the PartyState of the indicated Party.
   * @param {Party} party
   * @param {PartyState} state
   * @returns {{before: PartyState, after: PartyState}}
   * @private
   */
  _setPartyState (party, state) {
    this._assertValid();
    assert(party);
    assert(state);

    const partyKey = party.publicKey;
    const partyKeyStr = keyToString(partyKey);

    const before = this._getPartyState(party);
    if (before === state) {
      log(`Party ${partyKeyStr} already ${state}`);
      return { before, after: state };
    }

    this._partyState.set(partyKeyStr, state);

    switch (state) {
      case PartyState.OPEN:
        party.open();
        this.emit('party:open', partyKey);
        break;
      case PartyState.CLOSED:
        party.close();
        this.emit('party:close', partyKey);
        break;
    }

    log(`Party ${partyKeyStr} ${state} (${before})`);

    return {
      before,
      after: state
    };
  }
}
