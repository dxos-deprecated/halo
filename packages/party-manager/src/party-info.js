//
// Copyright 2020 DxOS
//

import assert from 'assert';
import EventEmitter from 'events';

import { humanize, keyToString } from '@dxos/crypto';

import { PartyMemberInfo } from './party-member-info';

/**
 * Party and Party-membership information.
 *
 * @event PartyInfo#'update' fires whenever PartyInfo is updated directly or a change is made to PartyMemberInfo.
 * @type {PublicKey}
 */
export class PartyInfo extends EventEmitter {
  /** @type {PublicKey} */
  _publicKey;

  /** @type {Object} */
  _properties;

  /** @type {Map<string, PartyMemberInfo>} */
  _members = new Map();

  /** @type {PartyManager} */
  __partyManager;

  /**
   * @param {PublicKey} publicKey
   * @param {PartyManager} partyManager
   */
  constructor (publicKey, partyManager) {
    super();
    assert(Buffer.isBuffer(publicKey));

    this._publicKey = publicKey;
    this.__partyManager = partyManager;

    // Any change to the Party may mean a change in membership.
    this.__partyManager.on('party:update', (partyKey) => {
      if (partyKey.equals(this._publicKey)) {
        this.updateMembershipFromParty();
      }
    });
  }

  get publicKey () {
    return this._publicKey;
  }

  get displayName () {
    const { displayName } = this.getProperties();
    return displayName || humanize(this._publicKey);
  }

  get members () {
    return Array.from(this._members.values());
  }

  /**
   * Sets the Party properties. (Called during message processing.)
   * @package
   * @param properties
   */
  setProperties (properties) {
    this._properties = properties;
    this.emit('update');
  }

  /**
   * Returns the Party properties.
   * @returns {Object}
   */
  getProperties () {
    return this._properties ? { ...this._properties } : {};
  }

  /**
   * Update PartyMemberInfo list from current Party key membership.
   * @package
   */
  updateMembershipFromParty () {
    const party = this.__partyManager.getParty(this._publicKey);
    if (party) {
      for (const key of party.memberKeys) {
        if (!key.equals(this._publicKey)) {
          const keyStr = keyToString(key);
          if (!this._members.has(keyStr)) {
            const member = new PartyMemberInfo(key, this, this.__partyManager);
            this._members.set(keyStr, member);
            member.on('update', () => this.emit('update', member));
            this.emit('update', member);
          }
        }
      }
    }
  }
}
