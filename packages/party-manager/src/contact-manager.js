//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import { diff, applyChange } from 'deep-diff';
import { keyToString } from '@dxos/crypto';

export const CONTACT_TYPE = 'dxos.halo.Contact';

const log = debug('dxos:party-manager:contact-manager');

/**
 * @typedef Contact
 * @property {PublicKey} publicKey
 * @property {string} displayName
 */

/**
 * Convert PartyMemberInfo into a Contact.
 * @param {PartyMemberInfo} partyMemberInfo
 * @returns {Contact}
 */
const toContact = (partyMemberInfo) => {
  const { publicKey, displayName } = partyMemberInfo;
  return { publicKey, displayName };
};

/**
 * Manages the storage and retrieval of Contacts from across all Parties.
 */
export class ContactManager {
  _model = null;
  _started = false;
  _handle = null;
  _buffer = new Map();

  /**
   * Set the Model to use for storage.
   * @param {Model} model
   */
  setModel (model) {
    this._model = model;
  }

  /**
   * Add a Contact from its PartyMemberInfo.
   * @param {PartyMemberInfo} partyMemberInfo
   */
  addContact (partyMemberInfo) {
    // Don't store ourselves as a contact.
    if (partyMemberInfo.isMe) {
      return;
    }

    const contact = toContact(partyMemberInfo);
    this._buffer.set(keyToString(partyMemberInfo.publicKey), contact);
    log('ADD', keyToString(contact.publicKey), contact);
  }

  /**
   * Returns an Array of all known Contacts across all Parties.
   * @returns {Contact[]}
   */
  getContacts () {
    const buffered = Array.from(this._buffer.values());
    const stored = this._model ? this._model.getObjectsByType(CONTACT_TYPE)
      .map(item => item.properties)
      .filter(contact => !buffered.find(entry => entry.publicKey.equals(contact.publicKey))) : [];
    return [...buffered, ...stored];
  }

  /**
   * Start writing Contacts to storage.  Until 'start' is called, contacts may be added, but they
   * will not be written to storage.  This should be called once after all the initial 'load' operations
   * are complete.
   */
  start () {
    assert(!this._interval);
    log('START');

    this._started = true;
    this._interval = setInterval(() => {
      this._flush();
    }, 200);
  }

  /**
   * Stop writing to storage.
   */
  stop () {
    log('STOP');

    if (this._interval) {
      clearInterval(this._interval);
      this._interval = null;
    }
    this._flush();
    this._started = false;
  }

  /**
   * Destroy (and stop).
   * @returns {Promise<void>}
   */
  async destroy () {
    this.stop();
    if (this._model) {
      await this._model.destroy();
    }
  }

  _flush () {
    if (!this._model || !this._buffer.size) {
      return;
    }

    const buffer = Array.from(this._buffer.values());
    this._buffer.clear();

    const counts = {
      buffer: buffer.length,
      create: 0,
      update: 0,
      existing: 0
    };

    const existing = this._model.getObjectsByType(CONTACT_TYPE);
    counts.existing = existing.length;

    for (const contact of buffer) {
      const contactKey = keyToString(contact.publicKey);

      const item = existing.find(item => item.properties.publicKey.equals(contact.publicKey));
      if (!item) {
        log('CREATE', contactKey, contact);
        this._model.createItem(CONTACT_TYPE, contact);
        counts.create++;
      } else {
        const differences = diff(item.properties, contact);
        if (differences) {
          const changedProperties = {};
          for (const change of differences) {
            applyChange(changedProperties, null, change);
          }
          log('UPDATE', contactKey, changedProperties);
          this._model.updateItem(item.id, changedProperties);
          counts.update++;
        }
      }
    }

    log('FLUSH', counts);
  }
}
