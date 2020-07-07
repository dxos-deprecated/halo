//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

import { Command } from './constants';

export const createGreetingBeginMessage = () => {
  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.BEGIN
  };
};

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

export const createGreetingFinishMessage = (secret) => {
  assert(Buffer.isBuffer(secret));

  return {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.FINISH,
    secret
  };
};

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
