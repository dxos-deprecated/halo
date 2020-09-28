//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import get from 'lodash.get';

import { isEnvelope } from '../party/party-credential';
import { createDateTimeString } from '../proto/datetime';

/**
 * Unwrap a SignedMessage from its Envelopes.
 * @param {SignedMessage} message
 * @return {SignedMessage} message
 */
const unwrapEnvelopes = (message) => {
  // Unwrap any Envelopes
  while (isEnvelope(message)) {
    message = message.signed.payload.contents.contents.payload;
  }
  return message;
};

/**
 * Extract the contents of a SignedMessage
 * @param {SignedMessage} message
 * @return {Message} message
 */
const extractContents = (message) => {
  // Unwrap any payload.
  while (message.signed || message.payload) {
    message = message.signed || message.payload;
  }
  return message;
};

/**
 * Creates a JoinedParty message for writing to the Halo so that all devices belonging to
 * the Identity can know about the Party.
 * @param {PublicKey} partyKey
 * @param {PublicKey} deviceKey
 * @param {PublicKey} feedKey
 * @param {KeyHint[]} hints
 * @param {string} [created]
 * @return {Message}
 */
export const createJoinedPartyMessage = (partyKey, deviceKey, feedKey, hints, created) => {
  assert(partyKey);
  assert(deviceKey);
  assert(feedKey);
  if (hints) {
    assert(Array.isArray(hints));
  }

  const payload = {
    __type_url: 'dxos.credentials.identity.JoinedParty',
    partyKey,
    deviceKey,
    feedKey,
    hints,
    created: created || createDateTimeString()
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload
  };
};

/**
 * Creates a DeviceInfo SignedMessage.
 * @param {Keyring} keyring
 * @param {string} displayName
 * @param {KeyRecord} deviceKey
 * @return {Message}
 */
export const createDeviceInfoMessage = (keyring, displayName, deviceKey) => {
  assert(keyring);
  assert(displayName);
  assert(deviceKey);

  const message = {
    __type_url: 'dxos.credentials.identity.DeviceInfo',
    publicKey: deviceKey.publicKey,
    displayName
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [deviceKey])
  };
};

/**
 * Creates a IdentityInfo SignedMessage.
 * @param {Keyring} keyring
 * @param {string} displayName
 * @param {KeyRecord} identityKey
 * @return {Message}
 */
export const createIdentityInfoMessage = (keyring, displayName, identityKey) => {
  assert(keyring);
  assert(displayName);
  assert(identityKey);

  const message = {
    __type_url: 'dxos.credentials.identity.IdentityInfo',
    publicKey: identityKey.publicKey,
    displayName
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [identityKey])
  };
};

/**
 * Returns true if the message is an Identity-related message, else false.
 * @param {Message} message
 * @return {boolean}
 */
export const isIdentityMessage = (message) => {
  message = extractContents(unwrapEnvelopes(message));
  const type = get(message, '__type_url');

  // Since message.payload may not exist, make safe and return false.
  return (type !== undefined) ? type.startsWith('dxos.credentials.identity.') : false;
};

/**
 * Returns true if the message is a JoinedParty message, else false.
 * @param {Message} message
 * @return {boolean}
 */
export const isJoinedPartyMessage = (message) => {
  const type = get(message, 'payload.__type_url');
  return type === 'dxos.credentials.identity.JoinedParty';
};

/**
 * Returns true if the message is a DeviceInfo message, else false.
 * @param {SignedMessage} message
 * @return {boolean}
 */
export const isDeviceInfoMessage = (message) => {
  message = extractContents(unwrapEnvelopes(message));

  return message.__type_url === 'dxos.credentials.identity.DeviceInfo';
};

/**
 * Returns true if the message is a IdentityInfo message, else false.
 * @param {SignedMessage} message
 * @return {boolean}
 */
export const isIdentityInfoMessage = (message) => {
  message = extractContents(unwrapEnvelopes(message));

  return message.__type_url === 'dxos.credentials.identity.IdentityInfo';
};
