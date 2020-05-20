//
// Copyright 2020 DxOS
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';

import { waitForEvent } from '@dxos/async';
import {
  Greeter,
  GreeterPlugin,
  Keyring,
  KeyType,
  admitsKeys,
  createEnvelopeMessage
} from '@dxos/credentials';
import { randomBytes, keyToString, keyToBuffer } from '@dxos/crypto';

import { greetingProtocolProvider } from './party-protocol-provider';

const log = debug('dxos:party-manager:greeting-responder');

/**
 * GreetingResponder transitions through the following states:
 * @type {GreetingState}
 */
export const GreetingState = Object.freeze({
  INITIALIZED: 'INITIALIZED', // Initial state.
  LISTENING: 'LISTENING', // After INITIALIZED, now listening for initiator connections.
  CONNECTED: 'CONNECTED', // An initiator has connected. Reverts to LISTENING if this initiator fails.
  SUCCEEDED: 'SUCCEEDED', // An initiator succeeded and has been admitted. Only one successful initiator is permitted.
  STOPPED: 'STOPPED', // No longer listening.
  DESTROYED: 'DESTROYED' // Responder no longer usable.
});

/**
 * Listens for greeting connections from invitees for a specific invitation specified by an invitation descriptor.
 * Upon successful greeting, the peer is admitted into the Party specified in the invitation descriptor.
 */
export class GreetingResponder extends EventEmitter {
  /** @type {Party} */
  _party;

  /** @type {NetworkManager} */
  _networkManager;

  /** @type {GreetingState} */
  _state;

  /** @type {Greeter} */
  _greeter;

  /** @type {GreeterPlugin} */
  _greeterPlugin;

  /** @type {Buffer} */
  _swarmKey;

  /**
   * @param {Party} party
   * @param {PartyManager} partyManager
   * @param {Keyring} keyring
   * @param {NetworkManager} networkManager
   */
  constructor (party, partyManager, keyring, networkManager) {
    super();
    assert(party);
    assert(partyManager);
    assert(keyring);
    assert(networkManager);

    this._party = party;
    this._partyManager = partyManager;
    this._keyring = keyring;
    this._networkManager = networkManager;

    this._swarmKey = randomBytes(32);
    this._greeter = new Greeter(
      party.publicKey,
      async messages => this._writeCredentialsToParty(messages),
      async () => this._gatherHints()
    );
    this._greeterPlugin = new GreeterPlugin(this._swarmKey, this._greeter.createMessageHandler());

    this._state = GreetingState.INITIALIZED;
  }

  /**
   * Accessor for UI to display status to the user.
   * Return the current state for this Greeting Responder (waiting, peer connected, successful auth, auth failed, etc).
   * @return {GreetingState}
   */
  get state () {
    return this._state;
  }

  /**
   * Listen for connections from invitee peers.
   * @param {SecretValidator} secretValidator
   * @param {SecretProvider} [secretProvider]
   * @param {function} [onFinish] A function to be called when the invitation is closed (successfully or not).
   * @param {int} [expiration] Date.now()-style timestamp of when this invitation should expire.
   * @returns {InvitationDescriptor}
   */
  // TODO(telackey): Change to nounVerb form.
  async invite (secretValidator, secretProvider, onFinish, expiration) {
    assert(secretValidator);
    assert(this._state === GreetingState.LISTENING);

    let timeoutTimer;
    const cleanup = async () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
      }
      if (onFinish) {
        try {
          await onFinish();
        } catch (err) {
          log(err);
        }
      }
      return this.destroy();
    };

    // TODO(telackey): This seems fragile - how do we know expiration is in the future?
    if (expiration) {
      timeoutTimer = setTimeout(cleanup, expiration - Date.now());
    }

    const invitation = this._greeter.createInvitation(this._party.publicKey, secretValidator,
      secretProvider, cleanup, expiration);

    // TODO(dboreham): Add tests for idempotence and transactional integrity over the greet flow.
    this._greeterPlugin.once('peer:joined', (joinedPeerId) => {
      if (keyToString(joinedPeerId) === invitation.id) {
        log(`Initiator connected: ${keyToString(joinedPeerId)}`);
        this._state = GreetingState.CONNECTED;
        this.emit('connected', invitation.id);
      } else {
        log(`Unexpected initiator connected: ${keyToString(joinedPeerId)}`);
      }
    });

    return keyToBuffer(invitation.id);
  }

  /**
   * Start listening for connections.
   */
  async start () {
    assert(this._state === GreetingState.INITIALIZED);

    // As the Greeter, use the topic as our peerId.
    // (For reasons why see detailed comment on greetClient).
    await this._networkManager.joinProtocolSwarm(this._swarmKey,
      greetingProtocolProvider(this._swarmKey, this._swarmKey, [this._greeterPlugin]));

    log(`Greeting for: ${keyToString(this._party.publicKey)} on swarmKey ${keyToString(this._swarmKey)}`);

    this._state = GreetingState.LISTENING;
    return this._swarmKey;
  }

  /**
   * Stop listening for connections. Until destroy() is called, getState() continues to work.
   */
  async stop () {
    log('Stopping');
    if (this._swarmKey) {
      await this._networkManager.leaveProtocolSwarm(this._swarmKey);
    }
    this._state = GreetingState.STOPPED;
    log('Stopped');
  }

  /**
   * Call to clean up. Subsequent calls to any method have undefined results.
   */
  async destroy () {
    await this.stop();
    this._greeter = null;
    this._swarmKey = null;
    this._state = GreetingState.DESTROYED;
    log('Destroyed');
  }

  /**
   * Callback which writes the Invitee's messages to the Party, signed by our key.
   * @param {Message[]} messages
   * @return {Promise<[Message]>}
   * @private
   */
  async _writeCredentialsToParty (messages) {
    assert(this._state === GreetingState.CONNECTED);

    // These messages will be self-signed by keys not yet admitted to the Party,, so we cannot check
    // for a trusted key, only that the signatures are valid.
    for (const message of messages) {
      const ok = Keyring.validateSignatures(message.payload);
      if (!ok) {
        throw new Error('Bad signature');
      }
    }

    const deviceKey = this._keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));
    const deviceKeyChain = Keyring.buildKeyChain(deviceKey.publicKey,
      this._partyManager.identityManager.identityHub.memberCredentials,
      this._partyManager.identityManager.identityHub.memberFeeds);

    const writeFeed = await this._partyManager.getWritableFeed(this._party.publicKey);

    // Place the self-signed messages inside an Envelope, sign then write the signed Envelope to the Party.
    const envelopes = [];
    for await (const message of messages) {
      const myAdmits = admitsKeys(message);
      const partyMessageWaiter = waitForEvent(this._partyManager, 'party:update',
        (eventPartyKey) => {
          let matchCount = 0;
          if (eventPartyKey.equals(this._party.publicKey)) {
            for (const key of myAdmits) {
              if (this._party.isMemberKey(key) || this._party.isMemberFeed(key)) {
                matchCount++;
              }
            }
          }
          return matchCount === myAdmits.length;
        });

      const envelope = createEnvelopeMessage(this._keyring, this._party.publicKey, message, deviceKeyChain);
      writeFeed.append(envelope);

      await partyMessageWaiter;
      envelopes.push(envelope);
    }
    this._state = GreetingState.SUCCEEDED;

    log('Wrote messages to local party feed');
    // Return the signed messages to the caller because copies are sent back to the invitee.
    return envelopes;
  }

  /**
   * Callback to gather member key and feed "hints" for the Invitee.
   * @return {KeyHint[]}
   * @private
   */
  _gatherHints () {
    assert(this._state === GreetingState.SUCCEEDED);

    const memberKeys = this._party.memberKeys.map(publicKey => {
      return {
        publicKey,
        type: this._party.keyring.getKey(publicKey).type
      };
    });

    const memberFeeds = this._party.memberFeeds.map(publicKey => {
      return {
        publicKey,
        type: KeyType.FEED
      };
    });

    return [...memberKeys, ...memberFeeds];
  }
}
