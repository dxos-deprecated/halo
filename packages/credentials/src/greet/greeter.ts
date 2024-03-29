//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { PublicKeyLike, PublicKey } from '@dxos/crypto';
import { ERR_EXTENSION_RESPONSE_FAILED } from '@dxos/protocol';

import { Keyring } from '../keys';
import { getPartyCredentialMessageType } from '../party';
import { PartyCredential, Message, KeyHint, Command } from '../proto';
import { PeerId } from '../typedefs';
import {
  ERR_GREET_INVALID_COMMAND,
  ERR_GREET_INVALID_INVITATION,
  ERR_GREET_INVALID_MSG_TYPE,
  ERR_GREET_INVALID_NONCE,
  ERR_GREET_INVALID_PARTY,
  ERR_GREET_INVALID_SIGNATURE,
  ERR_GREET_INVALID_STATE
} from './error-codes';
import { Invitation, InvitationOnFinish, SecretProvider, SecretValidator } from './invitation';

const log = debug('dxos:creds:greet');

export type PartyWriter = (params: Message[]) => Promise<Message[]>;
export type HintProvider = (params: Message[]) => Promise<KeyHint[]>;

/**
 * Reference Greeter that uses useable, single-use "invitations" to authenticate the invitee.
 */
export class Greeter {
  _partyKey?: PublicKey;
  _partyWriter?: PartyWriter;
  _hintProvider?: HintProvider;
  _invitations = new Map<string, Invitation>();

  /**
   * For a Greeter, all parameters must be properly set, but for the Invitee, they can be omitted.
   * TODO(telackey): Does it make sense to separate out the Invitee functionality?
   * @param {PublicKeyLike} [partyKey] The publicKey of the target Party.
   * @param {function} [partyWriter] Callback function to write messages to the Party.
   * @param {function} [hintProvider] Callback function to gather feed and key hints to give to the invitee.
   */
  constructor (partyKey?: PublicKeyLike, partyWriter?: PartyWriter, hintProvider?: HintProvider) {
    if (partyKey || partyWriter || hintProvider) {
      assert(partyKey);
      assert(partyWriter);
      assert(hintProvider);
    }

    this._partyKey = partyKey ? PublicKey.from(partyKey) : undefined;
    this._partyWriter = partyWriter;
    this._hintProvider = hintProvider;
  }

  /**
   * Issues a new invitation for the indicated Party.  The secretProvider is a function
   * for obtaining a secret that the invitee must provide for verification.  If present,
   * expiration should be a Date.
   * @param partyKey
   * @param {SecretValidator} secretValidator
   * @param {SecretProvider} [secretProvider]
   * @param {function} [onFinish]
   * @param {int} [expiration]
   * @returns {{id: string}}
   */
  createInvitation (partyKey: PublicKeyLike,
    secretValidator: SecretValidator,
    secretProvider?: SecretProvider,
    onFinish?: InvitationOnFinish,
    expiration?: number) {
    if (!this._partyKey!.equals(partyKey)) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_PARTY, `Invalid partyKey: ${partyKey}`);
    }

    const invitation = new Invitation(partyKey, secretValidator, secretProvider, onFinish, expiration);
    this._invitations.set(invitation.id.toString('hex'), invitation);

    // TODO(burdon): Would event handlers help with error handling?
    // (e.g., return Invitation and inv = xxx.createInvitation(); inv.on('finish'), inv.on('error'), etc?
    return {
      id: invitation.id
    };
  }

  // TODO(burdon): Remove (generic util that doesn't belong in this class).
  createMessageHandler () {
    return async (message: Command, remotePeerId: PeerId, peerId: PeerId) => {
      return this.handleMessage(message, remotePeerId, peerId);
    };
  }

  /**
   * Handle a P2P message from the Extension.
   * @param {Object} message
   * @param {PeerId} remotePeerId
   * @param {PeerId} peerId
   * @returns {Promise<{}>}
   */
  async handleMessage (message: Command, remotePeerId: PeerId, peerId: PeerId) {
    assert(message);
    assert(remotePeerId);
    assert(peerId);

    // The peer should be using their invitationId as their peerId.
    const invitationId = remotePeerId;
    const { command, params, secret } = message;

    // The BEGIN command is unique, in that it happens before auth and may require user interaction.
    if (command === Command.Type.BEGIN) {
      return this._handleBegin(invitationId);
    }

    assert(Buffer.isBuffer(secret));
    const invitation = await this._getInvitation(invitationId, secret);
    if (!invitation) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_INVITATION, 'Invalid invitation');
    }

    switch (command) {
      case Command.Type.HANDSHAKE: {
        return this._handleHandshake(invitation);
      }

      case Command.Type.NOTARIZE: {
        assert(Array.isArray(params));
        return this._handleNotarize(invitation, params);
      }

      case Command.Type.FINISH: {
        return this._handleFinish(invitation);
      }

      default:
        throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_COMMAND, `Invalid command: ${command}`);
    }
  }

  /**
   * Retrieves a valid invitation.
   * @param invitationId
   * @param secret
   * @returns {Promise<{Invitation}|null>}
   * @private
   */
  async _getInvitation (invitationId: Buffer, secret: Buffer) {
    const invitation = this._invitations.get(invitationId.toString('hex'));
    if (!invitation) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_INVITATION, `${invitationId} not found`);
    }

    if (!invitation.live) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_STATE, `${invitationId} dead`);
    }

    if (!invitation.began) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_STATE, `${invitationId} not begun`);
    }

    const valid = await invitation.validate(secret);
    if (!valid) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_INVITATION, `${invitationId} invalid`);
    }

    log('Auth valid for:', invitationId);
    return invitation;
  }

  /**
   * Finish and remove the invitation.
   * @param invitation
   * @private
   */
  async _handleFinish (invitation: Invitation) {
    await invitation.finish();
    this._invitations.delete(invitation.id.toString('hex'));
  }

  async _handleBegin (invitationId: Buffer) {
    const invitation = this._invitations.get(invitationId.toString('hex'));
    if (!invitation || !invitation.live || invitation.began || invitation.secret) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_STATE, 'Invalid invitation or out-of-order command sequence.');
    }

    // Mark it as having been presented and do any actions required
    // by specific Invitation type such as generate or gather the secret info.
    await invitation.begin();

    return {
      __type_url: 'dxos.credentials.greet.BeginResponse',
      info: {
        id: {
          __type_url: 'google.protobuf.BytesValue',
          value: invitation.id
        },
        authNonce: {
          __type_url: 'google.protobuf.BytesValue',
          value: invitation.authNonce
        }
      }
    };
  }

  async _handleHandshake (invitation: Invitation) {
    if (!invitation.began || invitation.handshook) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_STATE, 'Out-of-order command sequence.');
    }

    await invitation.handshake();
    return {
      __type_url: 'dxos.credentials.greet.HandshakeResponse',
      partyKey: invitation.partyKey,
      nonce: invitation.nonce
    };
  }

  async _handleNotarize (invitation: Invitation, params: any[]) {
    if (!invitation.handshook || invitation.notarized) {
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_STATE, 'Out-of-order command sequence.');
    }

    for await (const message of params) {
      // Every message needs to have our nonce inside it.
      if (!message.payload.signed.nonce.equals(invitation.nonce)) {
        throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_NONCE, `Invalid nonce: ${message.payload.signed.nonce.toString('hex')}`);
      }

      // Only FEED_ADMIT and KEY_ADMIT messages are valid.
      const messageType = getPartyCredentialMessageType(message);
      if (messageType !== PartyCredential.Type.KEY_ADMIT && messageType !== PartyCredential.Type.FEED_ADMIT) {
        throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_MSG_TYPE, `Invalid type: ${messageType}`);
      }

      // The signature needs to check out, but we cannot check for an already trusted key, since these messages
      // will all be self-signed.
      const verified = Keyring.validateSignatures(message.payload);
      if (!verified) {
        throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_GREET_INVALID_SIGNATURE, 'Invalid signature');
      }
    }

    // TODO(dboreham): Add useful data here (peer id, key?)
    log('Admitting new node after successful greeting.');

    assert(this._partyWriter);
    assert(this._hintProvider);

    // Write the supplied messages to the target Party.
    const copies = await this._partyWriter(params);

    // Retrieve the hinted feed and key info for the invitee.
    const hints = await this._hintProvider(params);

    await invitation.notarize();
    return {
      __type_url: 'dxos.credentials.greet.NotarizeResponse',
      copies,
      hints
    };
  }
}
