//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

/**
 * Create `dxos.credentials.auth.Auth` credentials.
 * @param {Keyring} keyring
 * @param {PublicKey} partyKey
 * @param {KeyRecord} identityKey
 * @param {KeyRecord|KeyChain} deviceKey
 * @param {KeyRecord} [feedKey]
 * @returns {Message}
 */
export const createAuthMessage = (keyring, partyKey, identityKey, deviceKey, feedKey) => {
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
      }, signingKeys)
  };
};
