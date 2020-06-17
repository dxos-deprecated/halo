//
// Copyright 2020 DxOS
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';

import { Filter, KeyType } from '@dxos/credentials';

import { DeviceManager } from './device-manager';
import { waitForCondition } from './util';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:party-manager:identity-manager');

/**
 * Provides Identity-related functionality for PartyManager.
 * @event IdentityManager#'ready' fires on initialization of a new Identity.
 * @event IdentityManager#'update' fires when IdentityInfo is updated.
 */
export class IdentityManager extends EventEmitter {
  /** @type {string} */
  _displayName;

  /** @type {DeviceManager} */
  _deviceManager;

  /** @type {PartyManager} */
  _partyManager;

  /** @type {Message} */
  _identityInfoMessage;

  /**
   * @param {PartyManager} partyManager
   */
  constructor (partyManager) {
    super();

    assert(partyManager);

    this._partyManager = partyManager;
    this._deviceManager = new DeviceManager(this._partyManager);
  }

  /**
   * @return {PublicKey}
   */
  get publicKey () {
    const key = this.keyRecord;
    return key ? key.publicKey : undefined;
  }

  /**
   * @return {KeyRecord}
   */
  get keyRecord () {
    return this._partyManager.keyRing.findKey(Filter.matches({
      type: KeyType.IDENTITY,
      own: true,
      trusted: true
    }));
  }

  /**
   * @return {Party}
   */
  get halo () {
    return this.hasIdentity() ? this._partyManager.getParty(this.publicKey) : undefined;
  }

  /**
   * Return the IdentityInfo message for our Identity.
   * @package
   * @returns {Message}
   */
  get identityInfoMessage () {
    return this._identityInfoMessage;
  }

  /**
   * Return the identity genesis message for our Identity.
   * @package
   * @returns {Message}
   */
  get identityGenesisMessage () {
    return this.halo
      ? this.halo.memberCredentials.get(this.keyRecord.key)
      : undefined;
  }

  /**
   * @return {string}
   */
  get displayName () {
    return this._displayName;
  }

  /**
   * @return {DeviceManager}
   */
  get deviceManager () {
    return this._deviceManager;
  }

  /**
   * Test if an identity key has been configured.
   * @return {boolean}
   */
  hasIdentity () {
    return !!this.keyRecord;
  }

  /**
   * Test if an identity halo has been configured.
   * @return {boolean}
   */
  async isInitialized () {
    if (!this.hasIdentity()) {
      return false;
    }

    return this._partyManager.hasWritableFeed(this.publicKey);
  }

  /**
   * Allows party-processor to inject information from identity info messages.
   * @package
   * @param {Message} message
   */
  setIdentityInfoMessage (message) {
    assert(!this._identityInfoMessage, 'IdentityInfo can only be set once.');

    // TODO(telackey): We are currently relying on the message processor to have done all the signature and
    // other verification checks (eg, key match) before this is called. Would it be better to move those checks here?

    const { payload: { signed: { payload } } } = message;
    const { displayName } = payload;
    if (displayName) {
      this._displayName = displayName;
    }

    this._identityInfoMessage = message;
    this.emit('update', this.publicKey, payload);
  }

  /**
   * Creates an Halo.
   */
  // TODO(dboreham): Better name for this method.
  async initializeForNewIdentity (props = {}) {
    assert(this.keyRecord);
    assert(this.deviceManager.keyRecord);
    const hasHalo = await this.isInitialized();
    assert(!hasHalo, 'Halo already exists');

    // Create base identity halo party.
    const party = await this._partyManager._createParty(this.keyRecord, this.deviceManager.keyRecord, props);
    await this.waitForIdentity();

    this.emit('ready', this.publicKey, party);
    return party;
  }

  /**
   * Returns a Promise that resolves when the Halo has been opened and all the messages needed for the
   * current device's KeyChain have been processed.
   * @returns {Promise<*>}
   * @package
   */
  async waitForIdentity () {
    const hasHalo = await this.isInitialized();
    if (!hasHalo) {
      return Promise.resolve();
    }

    return Promise.all([
      waitForCondition(() => this.halo),
      waitForCondition(() => this.identityGenesisMessage),
      waitForCondition(() => this.deviceManager.keyChain)
    ]);
  }
}
