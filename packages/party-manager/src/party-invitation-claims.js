//
// Copyright 2020 DxOS
//

import assert from 'assert';
import debug from 'debug';

import { waitForEvent, noop } from '@dxos/async';
import { Keyring, KeyType, GreetingCommandPlugin, createGreetingClaimMessage, codec } from '@dxos/credentials';
import { keyToString, randomBytes } from '@dxos/crypto';

import { InvitationDescriptor, InvitationDescriptorType } from './invitation-descriptor';
import { GreetingState } from './greeting-responder';
import { greetingProtocolProvider } from './party-protocol-provider';
import { PartyInvitationClaimHandler } from '@dxos/credentials/src/greet';

const log = debug('dxos:party-manager:party-invitation-claimer');

const DEFAULT_TIMEOUT = 30000;

/**
 * Attempts to connect to a greeting responder to 'redeem' an invitation, potentially with some out-of-band
 * authentication check, in order to be admitted to a Party.
 */
export class PartyInvitationClaimer {
  /** @type {InvitationDescriptor} */
  _invitationDescriptor;

  /** @type {PartyManager} */
  _partyManager;

  /** @type {NetworkManager} */
  _networkManager;

  /** @type {GreetingCommandPlugin} */
  _greeterPlugin;

  /** @type {GreetingState} */
  _state;

  /**
   * @param {InvitationDescriptor} invitationDescriptor
   * @param {PartyManager} partyManager
   * @param {NetworkManager} networkManager
   */
  constructor (invitationDescriptor, partyManager, networkManager) {
    assert(invitationDescriptor);
    assert(partyManager);
    assert(networkManager);
    assert(InvitationDescriptorType.PARTY === invitationDescriptor.type);

    this._invitationDescriptor = invitationDescriptor;
    this._partyManager = partyManager;
    this._networkManager = networkManager;
    this._state = GreetingState.INITIALIZED;
  }

  get state () {
    return this._state;
  }

  /**
   * Initiate a connection to a greeting responder node.
   * @param {number} timeout Connection timeout (ms).
   */
  async connect (timeout = DEFAULT_TIMEOUT) {
    assert(this._state === GreetingState.INITIALIZED);

    const { swarmKey } = this._invitationDescriptor;

    // This is a temporary connection, there is no need to any special or permanent ID.
    const localPeerId = randomBytes();
    log('Local PeerId:', keyToString(localPeerId));

    this._greeterPlugin = new GreetingCommandPlugin(localPeerId, noop);

    log('Connecting');
    const peerJoinedWaiter = waitForEvent(this._greeterPlugin, 'peer:joined',
      () => this._greeterPlugin.peers.length, timeout);

    await this._networkManager.joinProtocolSwarm(swarmKey,
      greetingProtocolProvider(swarmKey, localPeerId, [this._greeterPlugin]));

    await peerJoinedWaiter;
    log('Connected');
    this._state = GreetingState.CONNECTED;
  }

  /**
   * Called after connecting to claim the PartyInvitation and trigger interactive Greeting.
   * @return {InvitationDescriptor}
   */
  async claim () {
    assert(this._state === GreetingState.CONNECTED);
    const { invitation: invitationId } = this._invitationDescriptor;

    // Send to the first peer (any peer will do).
    const { peerId: responderPeerId } = this._greeterPlugin.peers[0].getSession();

    // We expect to receive a new swarm/rendezvousKey to use for the full Greeting process.
    const claimResponse = await this._greeterPlugin.send(responderPeerId, createGreetingClaimMessage(invitationId));
    const { id, rendezvousKey } = claimResponse;

    await this.disconnect();
    this._state = GreetingState.SUCCEEDED;

    return new InvitationDescriptor(InvitationDescriptorType.INTERACTIVE, rendezvousKey, id);
  }

  async disconnect () {
    const { swarmKey } = this._invitationDescriptor;
    await this._networkManager.leaveProtocolSwarm(swarmKey);
    this._state = GreetingState.DISCONNECTED;
  }

  async destroy () {
    await this.disconnect();
    this._invitationDescriptor = null;
    this._greeterPlugin = null;
    this._state = GreetingState.DESTROYED;
    log('Destroyed');
  }
}

/**
 * Create a function for handling PartyInvitations on the indicated Party. This is used by members of the Party
 * for responding to attempts to claim PartyInvitations which have been written to the Party.
 * @param {Party} party
 * @param {PartyManager} partyManager
 * @returns {function(*=, *=): Promise<{}>}
 */
export const makePartyInvitationClaimHandler = (party, partyManager) => {
  const claimHandler = new PartyInvitationClaimHandler(async (invitationID) => {
    const invitationMessage = party.getInvitation(invitationID);
    if (!invitationMessage) {
      throw new Error(`Invalid invitation ${keyToString(invitationID)}`);
    }

    // The Party will have validated the Invitation already, so we only need to extract the bits we need.
    const { inviteeKey } = invitationMessage.signed.payload;

    const secretValidator = async (invitation, secret) => {
      const { payload: authMessage } = codec.decode(secret);
      // Create a Keyring containing only the PublicKey of the contact we invited. Only a message signed by
      // by the matching private key, or a KeyChain which traces back to that key, will be verified.
      const keyring = new Keyring();
      await keyring.addPublicKey({
        publicKey: inviteeKey,
        type: KeyType.IDENTITY,
        trusted: true,
        own: false
      });

      return keyring.verify(authMessage) && party.publicKey.equals(authMessage.signed.payload.partyKey);
    };

    return partyManager.inviteToParty(party.publicKey, secretValidator);
  });

  return claimHandler.createMessageHandler();
};
