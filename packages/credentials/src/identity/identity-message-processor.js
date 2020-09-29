//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { keyToString } from '@dxos/crypto';

import { isDeviceInfoMessage, isIdentityInfoMessage } from '../identity';
import { Keyring } from '../keys';
import { isEnvelope, isSignedMessage } from '../party/party-credential';

const log = debug('dxos:creds:party');

/**
 * Process and manage IdentityInfo, DeviceInfo, and other "identity" Party messages.
 */
export class IdentityMessageProcessor {
  /**
   * @param {Party} party
   */
  constructor (party) {
    assert(party);

    /** @type {Party} */
    this._party = party;

    /** @type {Map<string, SignedMessage>} */
    this._infoMessages = new Map();
  }

  /**
   * Returns a map of SignedMessages used to describe keys. In many cases the contents are enough (see: getInfo)
   * but the original message is needed for copying into a new Party, as when an IdentityInfo message is copied
   * from the HALO Party to a Party that is being joined.
   * @return {Map<string, Message>}
   */
  get infoMessages () {
    return this._infoMessages;
  }

  /**
   * Get info for the specified key (if available).
   * @param {Buffer} publicKey
   * @return {IdentityInfo | DeviceInfo | undefined}
   */
  getInfo (publicKey) {
    assert(Buffer.isBuffer(publicKey));

    const message = this._infoMessages.get(keyToString(publicKey));
    // The saved copy is a SignedMessage, but we only want to return the contents.
    return message ? message.signed.payload : undefined;
  }

  /**
   * Process 'info' message (IdentityInfo, DeviceInfo, etc.)
   * @param {SignedMessage} message
   * @return {Promise<void>}
   */
  async processMessage (message) {
    assert(message);
    assert(isSignedMessage(message), `Not signed: ${JSON.stringify(message)}`);

    if (!this._party.verifySignatures(message)) {
      throw new Error(`Verification failed: ${JSON.stringify(message)}`);
    }

    if (isIdentityInfoMessage(message)) {
      return this._processIdentityInfoMessage(message);
    }

    if (isDeviceInfoMessage(message)) {
      log('WARNING: Not yet implemented.');
    }
  }

  /**
   * Process an IdentityInfo message.
   * @param {SignedMessage} message
   * @return {Promise<void>}
   * @private
   */
  async _processIdentityInfoMessage (message) {
    let partyKey;
    let signedIdentityInfo;
    let identityKey;

    if (isEnvelope(message)) {
      // If this message has an Envelope, the Envelope must match this Party.
      signedIdentityInfo = message.signed.payload.contents.contents.payload;
      identityKey = signedIdentityInfo.signed.payload.publicKey;
      partyKey = message.signed.payload.contents.partyKey;

      // Make sure the Envelope is signed with that particular Identity key or a chain that leads back to it.
      let signatureMatch = false;
      for (const signature of message.signatures) {
        // If this has a KeyChain, check its trusted parent key, else use this exact key.
        const signingKey = signature.keyChain
          ? this._party.findMemberKeyFromChain(signature.keyChain)
          : signature.key;
        if (signingKey && signingKey.equals(identityKey)) {
          signatureMatch = true;
          break;
        }
      }

      if (!signatureMatch) {
        throw new Error(`Invalid Envelope for IdentityInfo, not signed by proper key: ${JSON.stringify(message)}`);
      }
    } else {
      // If this message has no Envelope, the Identity key itself must match the Party.
      signedIdentityInfo = message;
      identityKey = signedIdentityInfo.signed.payload.publicKey;
      partyKey = identityKey;
    }

    // Check the inner message signature.
    if (Keyring.signingKeys(signedIdentityInfo).find(key => key.equals(identityKey)) < 0) {
      throw new Error(`Invalid IdentityInfo, not signed by Identity key: ${JSON.stringify(signedIdentityInfo)}`);
    }

    // Check the target Party matches.
    if (!partyKey || !partyKey.equals(this._party.publicKey)) {
      throw new Error(`Invalid party: ${keyToString(partyKey)}`);
    }

    // Check membership.
    if (!identityKey || !this._party.isMemberKey(identityKey)) {
      throw new Error(`Invalid IdentityInfo, not a member: ${keyToString(identityKey)}`);
    }

    this._infoMessages.set(keyToString(identityKey), signedIdentityInfo);
  }
}
