//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import EventEmitter from 'events';

import { useValue } from '@dxos/async';
import { keyToBuffer, keyToString, createId } from '@dxos/crypto';
import {
  Keyring,
  KeyType,
  PartyCredential,
  admitsKeys,
  getPartyCredentialMessageType,
  isDeviceInfoMessage,
  isIdentityInfoMessage,
  isIdentityMessage,
  isJoinedPartyMessage,
  isPartyCredentialMessage,
  isPartyInvitationMessage
} from '@dxos/credentials';

import { waitForCondition } from './util';

export const PartyProcessorState = Object.freeze({
  INITIALIZED: 'INITIALIZED',
  STARTED: 'STARTED',
  DESTROYED: 'DESTROYED'
});

const log = debug('dxos:party-manager:party-processor');

/**
 * Processes Identity and Party messages received from FeedStore's message stream,
 * delegate processing of messages to the relevant objects such that Party and Identity state is updated.
 *
 * @event PartyProcessor#'@package:device:info' fires when a DeviceInfo message has been processed.
 * @type {DeviceInfo}
 *
 * @event PartyProcessor#'@package:identity:info' fires when an IdentityInfo message has been processed.
 * @type {IdentityInfo}
 *
 * @event PartyProcessor#'@package:identity:joinedparty' fires when a JoinedParty message has been processed.
 * @type {PublicKey}
 *
 * @event PartyProcessor#'@package:sync' fires whenever the underlying message stream fires a 'sync' event.
 * @type {PublicKey}
 *
 * @event PartyProcessor#'@private:party:message' fires when any PartyCredentialMessage has been processed.
 * @type {PublicKey, PartyCredentialMessage}
 *
 * @event PartyProcessor#'@private:identity:message' fires when any IdentityMessage has been processed.
 * @type {PublicKey, IdentityMessage}
 */
export class PartyProcessor extends EventEmitter {
  /** @type {FeedStore} */
  _feedStore;

  /** @type {Keyring} */
  _keyRing;

  /** @type {ReadableStream} */
  _messageStream;

  /** @type {PartyProcessorState} */
  _state;

  /** @type {Set<string>} */
  _initLock = new Set();

  /** @type {Set<Message>} */
  _messageLock = new Set();

  /**
   * @param {PartyManager} partyManager
   * @param {FeedStore} feedStore
   * @param {Keyring} keyRing
   */
  constructor (partyManager, feedStore, keyRing) {
    super();
    assert(feedStore);
    assert(keyRing);
    assert(partyManager);

    this._feedStore = feedStore;
    this._keyRing = keyRing;
    this._partyManager = partyManager;
    this._state = PartyProcessorState.INITIALIZED;
  }

  /**
   * Opens a "fat" read stream over the entire FeedStore.
   * Party-related messages are dispatched to _processMessage.
   */
  async start () {
    assert(this._state === PartyProcessorState.INITIALIZED);

    // All the Party-related feeds need to be open for this to work properly.
    await this._feedStore.openFeeds((descriptor) => descriptor && descriptor.metadata && descriptor.metadata.topic);

    // Open a "fat" stream over all the Feeds in the store.
    // TODO(telackey): Would we ever need some start position other than 0?
    this._messageStream = this._feedStore.createReadStream(() => {
      return { live: true, start: 0 };
    });

    this._messageStream.on('sync', () => {
      this.emit('@package:sync');
    });

    this._messageStream.on('data', async (streamData) => {
      const { data, metadata } = streamData || {};
      // A Party-related message should certainly have a "topic" set on the Feed metadata.
      if (!data || !metadata || !metadata.topic) {
        return;
      }

      try {
        // We are only interested in Party messages.
        const partyKey = keyToBuffer(metadata.topic);
        const message = data; // TODO(dboreham): Hack.
        if (isPartyCredentialMessage(message)) {
          await this._processPartyMessage(partyKey, message);
        } else if (isPartyInvitationMessage(message)) {
          await this._processPartyMessage(partyKey, message);
        } else if (isIdentityMessage(message)) {
          await this._processIdentityMessage(partyKey, message);
        }
      } catch (err) {
        log('Error decoding/processing', err);
      }
    });

    this._messageStream.on('error', log);

    this._state = PartyProcessorState.STARTED;
  }

  /**
   * Stops reading, frees resources, and destroys the emitter.
   */
  destroy () {
    if (this._messageStream) {
      this._messageStream.destroy();
    }
    this._messageStream = undefined;
    this._state = PartyProcessorState.DESTROYED;
  }

  /**
   * Prevent races on initializing the Party between processing JoinedParty messages and PartyCredential messages.
   * @param {PublicKey} partyKey
   * @returns {Promise<Party>}
   * @private
   */
  async _safeGetOrInitParty (partyKey) {
    assert(Buffer.isBuffer(partyKey));

    let party = this._partyManager.getParty(partyKey);
    if (party) {
      return party;
    }

    const partyString = keyToString(partyKey);

    if (this._initLock.has(partyString)) {
      await waitForCondition(() => !this._initLock.has(partyString));
      party = this._partyManager.getParty(partyKey);
    } else {
      this._initLock.add(keyToString(partyKey));
      try {
        party = await this._partyManager.initParty(partyKey, true);
      } finally {
        this._initLock.delete(keyToString(partyKey));
      }
    }

    return party;
  }

  /**
   * Helper function to delay processing of out-of-order messages.
   * @param {PublicKey} partyKey
   * @param {function} processor  Must return truthy when done.
   * @returns {Promise<*>}
   * @private
   */
  __processWhenReady (partyKey, processor) {
    const [provider, resolver] = useValue();
    const id = createId();
    log(`Delayed message processing job: ${id}`);
    const listener = async (eventPartyKey) => {
      if (this._messageLock.has(id)) {
        log(`Job ${id} already being processed.`);
        return;
      }

      this._messageLock.add(id);
      try {
        if (eventPartyKey.equals(partyKey)) {
          if (await processor()) {
            resolver();
            this.off('@private:party:message', listener);
          }
        }
      } finally {
        this._messageLock.delete(id);
      }
    };
    this.on('@private:party:message', listener);
    return provider();
  }

  /**
   * Processes a single Halo IdentityInfo or DeviceInfo message.
   * @param {PublicKey} partyKey
   * @param {Message} message
   * @return {Promise<*>}
   * @private
   */
  async _processHaloMessage (partyKey, message) {
    assert(isIdentityMessage(message));
    assert(isDeviceInfoMessage(message) || isIdentityInfoMessage(message));
    assert(this._partyManager.isHalo(partyKey));

    const { payload: signedMessage, payload: { signed: { payload: info } } } = message;

    const processThisMessage = async () => {
      const halo = this._partyManager.identityManager.halo;
      if (!halo || !halo.isMemberKey(info.publicKey)) {
        return false;
      }
      if (halo.keyring.verify(signedMessage)) {
        if (isDeviceInfoMessage(message)) {
          this._partyManager.identityManager.deviceManager.setDeviceInfo(info);
          this.emit('@package:device:info', info);
        } else if (isIdentityInfoMessage(message)) {
          this._partyManager.identityManager.setIdentityInfoMessage(message);
          this.emit('@package:identity:info', info);
        }
      } else {
        log(`Unable to verify IdentityMessage: ${JSON.stringify(signedMessage)}`);
      }
      return true;
    };

    if (await processThisMessage()) {
      this.emit('@private:identity:message', partyKey, message);
    } else {
      // Looks like an out-of-order message. Set a self-canceling listener to process it as soon as we are ready.
      log('Not ready to process Halo message yet, delaying:', JSON.stringify(message));
      this.__processWhenReady(partyKey, processThisMessage).then(() => {
        log('Processed delayed Halo message:', JSON.stringify(message));
        this.emit('@private:identity:message', partyKey, message);
      });
    }
  }

  /**
   * Processes a single JoinedParty message.
   * @param {PublicKey} partyKey
   * @param {Message} message
   * @return {Promise<*>}
   * @private
   */
  async _processJoinedParty (partyKey, message) {
    assert(Buffer.isBuffer(partyKey));
    assert(isJoinedPartyMessage(message));
    assert(this._partyManager.isHalo(partyKey));

    const { payload: { partyKey: targetParty, deviceKey, feedKey, hints = [] } } = message;

    if (!this._partyManager.identityManager.deviceManager.publicKey.equals(deviceKey)) {
      const party = await this._safeGetOrInitParty(targetParty);

      // TODO(telackey): "Hints" are normally used in Greeting. We have a similar need here, but should these
      // still be called "hints", or something else?
      await party.takeHints([
        ...hints,
        { publicKey: feedKey, type: KeyType.FEED }
      ]);

      if (this._needsOpen(party)) {
        // Opening the Party may require credential messages that are still in our queue to process,
        // so do not 'await' on the opening here.
        // TODO(telackey): This promise will need to be saved when we implement full party life cycle support.
        this._partyManager.openParty(targetParty).then(() => {
          log(`Auto-opened ${keyToString(party.publicKey)}.`);
        });
      }
    }
    this.emit('@package:identity:joinedparty', targetParty);
    this.emit('@private:identity:message', targetParty, message);
  }

  /**
   * Processes a single IdentityMessage.
   * @param {PublicKey} partyKey
   * @param {Message} message
   * @return {Promise<*>}
   * @private
   */
  async _processIdentityMessage (partyKey, message) {
    assert(isIdentityMessage(message));

    if (this._partyManager.isHalo(partyKey)) {
      return isJoinedPartyMessage(message)
        ? this._processJoinedParty(partyKey, message)
        : this._processHaloMessage(partyKey, message);
    }
    if (isIdentityInfoMessage(message)) {
      const { payload: signedMessage, payload: { signed: { payload: info } } } = message;

      const processThisMessage = async () => {
        const party = this._partyManager.getParty(partyKey);
        const partyInfo = this._partyManager.getPartyInfo(partyKey);
        if (!party || !partyInfo ||
          !partyInfo.members.find(member => member.publicKey.equals(info.publicKey))) {
          return false;
        }

        if (party.keyring.verify(signedMessage)) {
          const memberInfo = partyInfo.members.find(member => member.publicKey.equals(info.publicKey));
          memberInfo.setDisplayName(info.displayName);
        } else {
          log(`Unable to verify IdentityMessage: ${JSON.stringify(signedMessage)}`);
        }
        return true;
      };

      if (await processThisMessage()) {
        this.emit('@private:party:identity:message', partyKey, message);
      } else {
        // Looks like an out-of-order message. Set a self-canceling listener to process it as soon as we are ready.
        log('Not ready to process IdentityInfo message yet, delaying:', JSON.stringify(message));
        this.__processWhenReady(partyKey, processThisMessage).then(() => {
          log('Processed delayed IdentityInfo message:', JSON.stringify(message));
          this.emit('@private:party:identity:message', partyKey, message);
        });
      }
    } else {
      log(`Unexpected IdentityMessage on ${keyToString(partyKey)}:`, JSON.stringify(message));
    }
  }

  /**
   * Processes a single Party-construction message.
   * @param {PublicKey} partyKey
   * @param {Message} message
   * @return {Promise<*>}
   * @private
   */
  async _processPartyMessage (partyKey, message) {
    if (isPartyCredentialMessage(message)) {
      const { payload: { signed: { payload: { contents: { partyKey: messagePartyKey } } } } } = message;
      assert(partyKey.equals(messagePartyKey), 'Mismatched party key.');
    } else if (isPartyInvitationMessage(message)) {
      const { payload: { signed: { payload: { partyKey: messagePartyKey } } } } = message;
      assert(partyKey.equals(messagePartyKey), 'Mismatched party key.');
    } else {
      throw new Error(`Wrong message type: ${message}`);
    }

    const party = await this._safeGetOrInitParty(partyKey);
    if (this._needsOpen(party)) {
      // Opening the Party may require credential messages that are still in our queue to process,
      // so do not 'await' on the opening here.
      // TODO(telackey): This promise will need to be saved when we implement full party life cycle support.
      this._partyManager.openParty(partyKey).then(() => {
        log(`Auto-opened ${keyToString(party.publicKey)}.`);
      });
    }

    // We can always process the GENESIS right away.
    const credentialType = isPartyCredentialMessage(message) && getPartyCredentialMessageType(message);
    if (credentialType === PartyCredential.Type.PARTY_GENESIS) {
      await party.processMessages([message]);
      this.emit('@private:party:message', partyKey, message);
      return;
    }

    const signingKeys = Keyring.signingKeys(message);
    const processThisMessage = async () => {
      for await (const signedBy of signingKeys) {
        if (party.isMemberKey(signedBy) || partyKey.equals(signedBy)) {
          await party.processMessages([message]);

          // If this is a FEED, update the PartyMemberInfo of the owner to include it in their "feeds" list.
          if (!this._partyManager.isHalo(partyKey) && credentialType === PartyCredential.Type.FEED_ADMIT) {
            const [feedKey] = admitsKeys(message);
            const admittedBy = party.getAdmittedBy(feedKey);
            if (!admittedBy.equals(partyKey)) {
              const partyInfo = this._partyManager.getPartyInfo(partyKey);
              // We know "admittedBy" information must exist in the Party or the FEED_ADMIT could not have been
              // processed. But admitting the feed is often done just after admitting a new member key, and
              // we don't know for sure if the event handler on PartyInfo has updated its member list with the
              // new member yet. Explicitly calling partyInfo.updateMembershipFromParty() means we don't have to wait
              // on event handling to update it for us.
              partyInfo.updateMembershipFromParty();
              const member = partyInfo.members.find(member => member.publicKey.equals(admittedBy));
              member.addFeed(feedKey);
            }
          }
          return true;
        }
      }
      return false;
    };

    if (await processThisMessage()) {
      this.emit('@private:party:message', partyKey, message);
    } else {
      // Looks like an out-of-order message. Set a self-canceling listener to process it as soon as we are ready.
      log('Not ready to process Party message yet, delaying:', JSON.stringify(message));
      this.__processWhenReady(partyKey, processThisMessage).then(() => {
        log('Processed delayed Party message:', JSON.stringify(message));
        this.emit('@private:party:message', partyKey, message);
      });
    }
  }

  /**
   * Does this Party need to be opened?
   * @param {Party} party
   * @returns {boolean}
   * @private
   */
  _needsOpen (party) {
    let needsOpen = !party.isOpen();
    // Always open the Halo, but for everything else we can check the subscription status.
    if (needsOpen && !this._partyManager.isHalo(party.publicKey)) {
      const info = this._partyManager.getPartyInfo(party.publicKey);
      needsOpen = info.subscribed;
    }
    return needsOpen;
  }
}
