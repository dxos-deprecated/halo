//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

import { Keyring } from '../keys';
import { KeyChain, KeyRecord, PublicKey, Message } from '../typedefs';

/**
 * Create `dxos.credentials.auth.Auth` credentials.
 */
export const createAuthMessage = (
  keyring: Keyring,
  partyKey: PublicKey,
  identityKey: KeyRecord,
  deviceKey: KeyRecord | KeyChain,
  feedKey?: KeyRecord,
  nonce?: Buffer
): Message => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(Buffer.isBuffer(identityKey.publicKey));
  assert(Buffer.isBuffer(deviceKey.publicKey));
  if (feedKey) {
    assert(Buffer.isBuffer(feedKey.publicKey));
  }

  const signingKeys = [deviceKey];
  if (feedKey) {
    signingKeys.push(feedKey);
  }

  return {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.auth.Auth',
        partyKey,
        identityKey: identityKey.publicKey,
        deviceKey: deviceKey.publicKey,
        feedKey: feedKey ? feedKey.publicKey : undefined
      }, signingKeys, nonce)
  };
};
