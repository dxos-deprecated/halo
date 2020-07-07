//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

import { Command } from './constants';

/**
 * Create a Greeting 'BEGIN' command message.
 * @returns {{__type_url: string, command: *}}
 */
export const createGreetingBeginMessage = () => {
  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.BEGIN
  };
};

/**
 * Create a Greeting 'HANDSHAKE' command message.
 * @param {Buffer} secret
 * @param {Any[]} params
 * @returns {{__type_url: string, secret: *, params: *[], command: *}}
 */
export const createGreetingHandshakeMessage = (secret, params = []) => {
  assert(Buffer.isBuffer(secret));
  assert(Array.isArray(params));

  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.HANDSHAKE,
    params,
    secret
  };
};

/**
 * Create a Greeting 'NOTARIZE' command message.
 * @param {Buffer} secret
 * @param {SignedMessage[]} credentialMessages
 * @returns {{__type_url: string, secret: *, params: *, command: *}}
 */
export const createGreetingNotarizeMessage = (secret, credentialMessages) => {
  assert(Buffer.isBuffer(secret));
  assert(Array.isArray(credentialMessages));

  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.NOTARIZE,
    params: credentialMessages,
    secret
  };
};

/**
 * Create a Greeting 'FINISH' command message.
 * @param {Buffer} secret
 * @returns {{__type_url: string, secret: *, command: *}}
 */
export const createGreetingFinishMessage = (secret) => {
  assert(Buffer.isBuffer(secret));

  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.FINISH,
    secret
  };
};

/**
 * Create a Greeting 'CLAIM' command message.
 * @param {Buffer} invitationID
 * @returns {{__type_url: string, params: [{__type_url: string, value: *}], command: *}}
 */
export const createGreetingClaimMessage = (invitationID) => {
  assert(Buffer.isBuffer(invitationID));

  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.CLAIM,
    params: [
      {
        __type_url: 'google.protobuf.BytesValue',
        value: invitationID
      }
    ]
  };
};

/**
 * Crate a Greeting ClaimResponse message.
 * @param {Buffer} id   The ID of the new invitation.
 * @param {Buffer} rendezvousKey   The swarm key to use for Greeting.
 * @returns {{__type_url: string, payload: {__type_url: string, rendezvousKey: *, id: *}}}
 */
export const createGreetingClaimResponse = (id, rendezvousKey) => {
  assert(id);
  assert(Buffer.isBuffer(rendezvousKey));

  return {
    __type_url: 'dxos.credentials.Message',
    payload: {
      __type_url: 'dxos.credentials.greet.ClaimResponse',
      id,
      rendezvousKey
    }
  };
};
