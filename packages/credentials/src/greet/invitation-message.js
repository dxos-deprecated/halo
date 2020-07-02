//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

import { randomBytes } from '@dxos/crypto';

/**
 * Create `dxos.credentials.greet.Invitation` message.
 * @param {Keyring} keyring
 * @param {PublicKey} partyKey
 * @param {KeyRecord} issuerKey
 * @param {KeyRecord} inviteeKey
 * @param {KeyRecord|KeyChain} [signingKey]
 * @returns {Message}
 */
export const createInvitationMessage = (keyring, partyKey, issuerKey, inviteeKey, signingKey) => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(Buffer.isBuffer(issuerKey.publicKey));
  assert(Buffer.isBuffer(inviteeKey.publicKey));
  if (!signingKey) {
    signingKey = issuerKey;
  }
  assert(Buffer.isBuffer(signingKey.publicKey));
  assert(keyring.hasSecretKey(signingKey));

  return {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.greet.Invitation',
        id: randomBytes(),
        partyKey,
        issuerKey: issuerKey.publicKey,
        inviteeKey: inviteeKey.publicKey
      }, [signingKey])
  };
};
