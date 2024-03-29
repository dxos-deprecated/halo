//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { ERR_EXTENSION_RESPONSE_FAILED } from '@dxos/protocol';

import { Command } from '../proto';
import { ERR_GREET_GENERAL, ERR_GREET_INVALID_COMMAND, ERR_GREET_INVALID_INVITATION } from './error-codes';
import { createGreetingClaimResponse } from './greeting-message';

const log = debug('dxos:creds:greet:claim');

export type PartyInvitationGreetingHandler = (invitationID: Buffer, remotePeerId: Buffer, peerId: Buffer) => Promise<any>;

export class PartyInvitationClaimHandler {
  _greetingHandler: PartyInvitationGreetingHandler;

  /**
   *
   * @param {function} greetingHandler
   */
  constructor (greetingHandler: PartyInvitationGreetingHandler) {
    assert(greetingHandler);

    this._greetingHandler = greetingHandler;
  }

  createMessageHandler () {
    return async (message: any, remotePeerId: Buffer, peerId: Buffer) => {
      return this.handleMessage(message, remotePeerId, peerId);
    };
  }

  /**
   * Handle a P2P message from the Extension.
   */
  async handleMessage (message: any, remotePeerId: Buffer, peerId: Buffer) {
    assert(message);
    assert(remotePeerId);
    assert(peerId);

    const { command, params = [] } = message;

    if (command !== Command.Type.CLAIM || params.length !== 1) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_COMMAND, 'Invalid command');
    }

    const { value: invitationID } = params[0];
    if (!Buffer.isBuffer(invitationID)) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_INVITATION, 'Invalid invitation');
    }

    try {
      const invitationDescriptor = await this._greetingHandler(invitationID, remotePeerId, peerId);
      log(invitationDescriptor);
      return createGreetingClaimResponse(invitationDescriptor.invitation, invitationDescriptor.swarmKey);
    } catch (err) {
      log(err);
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_GENERAL, 'Error handing off Invitation for Greeting.');
    }
  }
}
