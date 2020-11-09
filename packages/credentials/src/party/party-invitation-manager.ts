//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { keyToString } from '@dxos/crypto';

import { SignedMessage } from '../proto';
import { Party } from './party';

const log = debug('dxos:creds:party');

/**
 * A class to manage the lifecycle of invitations which are written to the Party.
 * @package
 */
export class PartyInvitationManager {
  _party: Party;
  _activeInvitations: Map<string, SignedMessage>;
  _invitationsByKey: Map<string, Set<string>>;

  constructor (party: Party) {
    assert(party);

    this._party = party;
    this._activeInvitations = new Map();
    this._invitationsByKey = new Map();

    this._party.on('admit:key', (keyRecord) => {
      const byKey = this._invitationsByKey.get(keyRecord.key) || new Set();
      for (const idStr of byKey) {
        log(`${keyRecord.key} admitted, deactivating Invitation ${idStr}.`);
        this._activeInvitations.delete(idStr);
      }
      this._invitationsByKey.delete(keyRecord.key);
    });
  }

  /**
   * Return the Message for `invitationID`, if known.
   */
  getInvitation (invitationID: Buffer) {
    return this._activeInvitations.get(invitationID.toString('hex'));
  }

  /**
   * Record a new PartyInvitation message.
   * @param {SignedMessage} invitationMessage
   */
  recordInvitation (invitationMessage: SignedMessage) {
    assert(invitationMessage);

    const invitation = this._verifyAndParse(invitationMessage);
    const idStr = keyToString(invitation.id);
    const keyStr = keyToString(invitation.inviteeKey);

    if (this._party.isMemberKey(invitation.inviteeKey)) {
      log(`Invitation ${idStr} is for existing member ${keyStr}`);
      return;
    }

    if (!this._activeInvitations.has(idStr)) {
      this._activeInvitations.set(idStr, invitationMessage);
      const byKey = this._invitationsByKey.get(keyStr) || new Set();
      byKey.add(idStr);
      this._invitationsByKey.set(keyStr, byKey);
    }
  }

  /**
   * Verify that the PartyInvitation message is properly formed and validly signed.
   * @returns {PartyInvitation}
   * @private
   */
  _verifyAndParse (invitationMessage: SignedMessage) {
    assert(invitationMessage);

    // Verify Message
    if (!this._party.verifySignatures(invitationMessage)) {
      throw new Error(`Unverifiable message: ${invitationMessage}`);
    }

    const { id, issuerKey, inviteeKey } = invitationMessage.signed.payload;

    assert(Buffer.isBuffer(id));
    assert(Buffer.isBuffer(issuerKey));
    assert(Buffer.isBuffer(inviteeKey));

    if (!this._party.isMemberKey(issuerKey)) {
      throw new Error(`Invalid issuer: ${invitationMessage}`);
    }

    return invitationMessage.signed.payload;
  }
}
