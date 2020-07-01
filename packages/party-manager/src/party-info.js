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
 * @event PartyInfo#'member:add' fires whenever PartyMemberInfo is added ('update' also fires).
 * @event PartyInfo#'member:update' fires whenever PartyMemberInfo is updated ('update' also fires).
 * @event PartyInfo#'subscription' fires whenever the subscription status of the PartyInfo changes ('update' also fires).
 * @event PartyInfo#'update' fires whenever PartyInfo attributes, settings, or properties are updated or
 *   PartyMemberInfo is added or changed.
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

  /** @type {Object} */
  _settings;

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

    // Echo some specific events under the general 'update' event.
    {
      const eventNames = ['member:add', 'member:update'];
      for (const eventName of eventNames) {
        this.on(eventName, (...args) => this.emit('update', ...args));
      }
    }
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

  get subscribed () {
    const { subscribed = true } = this.getSettings();
    return subscribed;
  }

  /**
   * Sets the Party properties. (Called during message processing.)
   * Party properties are universal and replicated to all Party members.
   * @package
   * @param properties
   */
  setProperties (properties) {
    this._properties = properties;
    this.emit('update');
  }

  /**
   * Sets the Party settings. (Called during message processing.)
   * Party settings are specific to this Identity and replicated on the Halo.
   * @package
   * @param settings
   */
  setSettings (settings) {
    const before = this._settings ? { ...this._settings } : {};
    this._settings = settings;

    this._emitSettingChangeEvents(before, this._settings);
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
   * Returns the Party settings.
   * @returns {Object}
   */
  getSettings () {
    return this._settings ? { ...this._settings } : {};
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
            member.on('update', () => this.emit('member:update', member));
            this.emit('member:add', member);
          }
        }
      }
    }
  }

  /**
   * Emit events related to setting changes.
   * @param {Object} before
   * @param {Object} after
   * @private
   */
  _emitSettingChangeEvents (before, after) {
    const { subscribed: beforeSub = true } = before || {};
    const { subscribed: afterSub = true } = after || {};

    if (beforeSub !== afterSub) {
      this.emit('subscription');
    }

    // TODO(telackey): other events go here.
  }
}
