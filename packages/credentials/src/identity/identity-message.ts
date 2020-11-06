//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import get from 'lodash/get';

import {unwrapEnvelopes, extractContents, unwrapMessage} from '../party/party-credential';
import {Keyring} from "../keys";
import {KeyRecord} from "../typedefs";
import {WithTypeUrl} from "../proto/any";
import {DeviceInfo, IdentityInfo, Message, SignedMessage} from "../proto";

/**
 * Creates a DeviceInfo SignedMessage.
 */
export const createDeviceInfoMessage = (keyring: Keyring, displayName: string, deviceKey: KeyRecord): Message => {
  assert(keyring);
  assert(displayName);
  assert(deviceKey);

  const message: WithTypeUrl<DeviceInfo> = {
    __type_url: 'dxos.credentials.identity.DeviceInfo',
    publicKey: deviceKey.publicKey,
    displayName
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [deviceKey])
  } as WithTypeUrl<Message>;
};

/**
 * Creates a IdentityInfo SignedMessage.
 */
export const createIdentityInfoMessage = (keyring: Keyring, displayName: string, identityKey: KeyRecord): Message => {
  assert(keyring);
  assert(displayName);
  assert(identityKey);

  const message: WithTypeUrl<IdentityInfo> = {
    __type_url: 'dxos.credentials.identity.IdentityInfo',
    publicKey: identityKey.publicKey,
    displayName
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [identityKey])
  } as WithTypeUrl<Message>;
};

/**
 * Returns true if the message is an Identity-related message, else false.
 * @param {Message} message
 * @return {boolean}
 */
export const isIdentityMessage = (message: Message | SignedMessage) => {
  message = extractContents(unwrapEnvelopes(unwrapMessage(message)));
  const type = get(message, '__type_url');

  // Since message.payload may not exist, make safe and return false.
  return (type !== undefined) ? type.startsWith('dxos.credentials.identity.') : false;
};

/**
 * Returns true if the message is a DeviceInfo message, else false.
 * @param {SignedMessage} message
 * @return {boolean}
 */
export const isDeviceInfoMessage = (message: Message | SignedMessage) => {
  message = extractContents(unwrapEnvelopes(unwrapMessage(message)));

  return get(message, '__type_url') === 'dxos.credentials.identity.DeviceInfo';
};

/**
 * Returns true if the message is a IdentityInfo message, else false.
 * @param {SignedMessage} message
 * @return {boolean}
 */
export const isIdentityInfoMessage = (message: Message | SignedMessage) => {
  message = extractContents(unwrapEnvelopes(unwrapMessage(message)));

  return get(message, '__type_url') === 'dxos.credentials.identity.IdentityInfo';
};
