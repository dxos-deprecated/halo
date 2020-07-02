//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { ERR_EXTENSION_RESPONSE_FAILED } from '@dxos/protocol';

import { Command } from './constants';
import { ERR_GREET_INVALID_COMMAND } from './error-codes';

const log = debug('dxos:creds:greet');

class IntroAuthorizer {
  /** @type {Party} */
  _party;

  /** @type {Map<string, Message>} */
  _activeInvitations;

  constructor (party) {
    assert(party);

    this._party = party;
    this._activeInvitations = new Map();

    this._party.on('admit:key', (keyRecord) => {
      if (this._activeInvitations.has(keyRecord.key)) {
        log(`${keyRecord.key} admitted, deactivating Invitation.`);
        this._activeInvitations.delete(keyRecord.key);
      }
    });
  }

  /**
   *
   * @param invitationMessage
   */
  recordInvitation (invitationMessage) {
    party.ke;
    this._activeInvitations.put;
  }
}

export class IntroExtension {
  constructor () {
  }

  createMessageHandler () {
    return async (peerId, message) => {
      return this.handleMessage(peerId, message);
    };
  }

  /**
   * Handle a P2P message from the Extension.
   * @param peerId
   * @param message
   * @returns {Promise<{}>}
   */
  async handleMessage (peerId, message) {
    assert(message);
    const { command, params, secret } = message;

    if (command !== Command.Type.INTRO) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_COMMAND, 'Invalid command');
    }
  }
}
