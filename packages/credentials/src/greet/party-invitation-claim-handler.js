//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { ERR_EXTENSION_RESPONSE_FAILED } from '@dxos/protocol';

import { Command } from './constants';
import { ERR_GREET_GENERAL, ERR_GREET_INVALID_COMMAND, ERR_GREET_INVALID_INVITATION } from './error-codes';
import { createGreetingClaimResponse } from './greeting-message';

const log = debug('dxos:creds:greet:claim');

export class PartyInvitationClaimHandler {
  /** @type {function} */
  _greetingHandler;

  /**
   *
   * @param {function} greetingHandler
   */
  constructor (greetingHandler) {
    assert(greetingHandler);

    this._greetingHandler = greetingHandler;
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
    const { command, params = [] } = message;

    if (command !== Command.Type.CLAIM || params.length !== 1) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_COMMAND, 'Invalid command');
    }

    const { value: invitationID } = params[0];
    if (!Buffer.isBuffer(invitationID)) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_INVITATION, 'Invalid invitation');
    }

    try {
      const invitationDescriptor = await this._greetingHandler(invitationID, peerId);
      log(invitationDescriptor);
      return createGreetingClaimResponse(invitationDescriptor.invitation, invitationDescriptor.swarmKey);
    } catch (err) {
      log(err);
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_GENERAL, 'Error handing off Invitation for Greeting.');
    }
  }
}
