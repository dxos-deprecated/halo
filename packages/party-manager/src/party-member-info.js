//
// Copyright 2020 DxOS
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';

import { waitForEvent } from '@dxos/async';
import { humanize, keyToString } from '@dxos/crypto';

const log = debug('dxos:party-manager:party-member-info');

/**
 * Information (displayName, etc.) about a Party member.
 *
 * @event PartyMemberInfo#'update' fires whenever a change is made
 * @type {PublicKey}
 */
export class PartyMemberInfo extends EventEmitter {
  /** @type {PublicKey} */
  _publicKey;

  /** @type {string} */
  _displayName;

  /** @type {PublicKey} */
  _admittedBy;

  /** @type {PublicKey[]} */
  _feeds = [];

  /** @type {PartyInfo} */
  __partyInfo;

  /** @type {PartyManager} */
  __partyManager;

  /**
   * @param {PublicKey} publicKey
   * @param {PartyInfo} partyInfo
   * @param {PartyManager} partyManager
   */
  constructor (publicKey, partyInfo, partyManager) {
    super();
    assert(Buffer.isBuffer(publicKey));
    assert(partyInfo);

    this._publicKey = publicKey;
    this.__partyInfo = partyInfo;
    this.__partyManager = partyManager;

    this._admittedBy = this._determineAdmittedBy();
    if (!this._admittedBy) {
      waitForEvent(this.__partyManager, 'update', (partyKey) => {
        if (partyKey.equals(partyInfo.publicKey)) {
          this._admittedBy = this._determineAdmittedBy();
        }
        return this._admittedBy;
      }).then(() => this.emit('update'));
    }
  }

  get publicKey () {
    return this._publicKey;
  }

  /**
   * What key was used to admit this member to the Party?
   * The `admittedBy` key for the Party creator will be the Party key.
   * @returns {PublicKey}
   */
  get admittedBy () {
    return this._admittedBy;
  }

  /**
   * The Feeds owned by this Identity.
   * @returns {PublicKey[]}
   */
  get feeds () {
    return this._feeds;
  }

  /**
   * Does this PartyMemberInfo correspond to the present Identity?
   * @returns {boolean}
   */
  get isMe () {
    return this.__partyManager.identityManager.hasIdentity() &&
      this.__partyManager.identityManager.publicKey.equals(this._publicKey);
  }

  /**
   * The displayName for this Party-member, if set. If this PartyMemberInfo is for the present Identity,
   * the displayName will always be identical to IdentityManager.displayName.
   * @returns {string}
   */
  get displayName () {
    if (this.isMe && this.__partyManager.identityManager.displayName) {
      return this.__partyManager.identityManager.displayName;
    }
    return this._displayName ? this._displayName : humanize(this._publicKey);
  }

  /**
   * Sets the displayName. (Called during message processing.)
   * @package
   * @param {string} value
   */
  setDisplayName (value) {
    this._displayName = value;
    this.emit('update');
  }

  /**
   * Adds a feed owned by the identity. (Called during message processing.)
   * @package
   * @param {PublicKey} feedKey
   */
  addFeed (feedKey) {
    assert(Buffer.isBuffer(feedKey));

    // TODO(telackey): Check with the Party that this is truly a memberFeed (and owned by this member)?
    if (!this._feeds.find(key => key.equals(feedKey))) {
      this._feeds.push(feedKey);
      this.emit('update');
    } else {
      log(`Already exists: ${keyToString(feedKey)}`);
    }
  }

  /**
   * Interrogate the Party to find which key admitted this key.
   * @returns {undefined|PublicKey}
   * @private
   */
  _determineAdmittedBy () {
    const party = this.__partyManager.getParty(this.__partyInfo.publicKey);
    return party ? party.getAdmittedBy(this._publicKey) : undefined;
  }
}
