//
// Copyright 2020 DXOS.org
//

import assert from 'assert';
import debug from 'debug';

import { waitForEvent } from '@dxos/async';
import { Keyring, KeyType, createDeviceInfoMessage } from '@dxos/credentials';
import { keyToString } from '@dxos/crypto';

import { InvitationDescriptor, InvitationDescriptorType } from './invitation-descriptor';
import { InviteDetails, InviteType } from './invite-details';

const log = debug('dxos:party-manager:device-manager');

// Non-class types used as parameters and return values in this file:

/**
 * @typedef DeviceInfo
 * @property {string} displayName
 * @property {PublicKey} key
 * @property {PublicKey} admittedBy
 */

/**
 * Interface through which device-related functionality in party-manager is accessed.
 */
export class DeviceManager {
  /** @type {PartyManager} */
  _partyManager;

  _deviceInfos = new Map();

  /**
   * @param {PartyManager} partyManager
   */
  constructor (partyManager) {
    assert(partyManager);

    this._partyManager = partyManager;
  }

  /**
   * @return {PublicKey|undefined}
   */
  get publicKey () {
    const key = this.keyRecord;
    return key ? key.publicKey : undefined;
  }

  /**
   * @return {KeyRecord}
   */
  get keyRecord () {
    const keyRecord = this._partyManager.keyRing.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));
    assert(keyRecord);
    return keyRecord;
  }

  /**
   * @return {KeyChain|undefined}
   */
  get keyChain () {
    let keyChain;

    try {
      const halo = this._partyManager.identityManager.halo;
      if (halo) {
        keyChain = Keyring.buildKeyChain(this.publicKey, halo.memberCredentials, halo.memberFeeds);
      }
    } catch (err) {
      // It is not unexpected to have an error building the key chain, as we may not have all the messages loaded yet,
      // in which case, we return an empty keychain.
      keyChain = undefined;
    }

    return keyChain;
  }

  /**
   * @return {string|undefined}
   */
  get displayName () {
    const { publicKey } = this;
    if (publicKey) {
      const info = this._deviceInfos.get(keyToString(publicKey));
      if (info) {
        return info.displayName;
      }
    }
    return undefined;
  }

  setDeviceInfo (deviceInfo) {
    this._deviceInfos.set(keyToString(deviceInfo.publicKey), deviceInfo);
  }

  /**
   * @return {DeviceInfo[]}
   */
  get devices () {
    const devices = Array.from(this._deviceInfos.values());
    // If the local device wasn't in devices, add it:
    if (!this._deviceInfos.has(keyToString(this.publicKey))) {
      devices.push({
        publicKey: this.publicKey,
        displayName: keyToString(this.publicKey)
      });
    }
    return devices;
  }

  /**
   * Invites a Device to join this Identity.
   * @param {SecretValidator} secretValidator
   * @param {SecretProvider} secretProvider
   * @param {InviteOptions} [options]
   * @returns {Promise<InvitationDescriptor>}
   */
  async addDevice (secretValidator, secretProvider, options = {}) {
    assert(secretValidator);
    assert(secretProvider);

    const identityKey = this._partyManager.identityManager.publicKey;
    const invitation = await this._partyManager.inviteToParty(identityKey,
      new InviteDetails(InviteType.INTERACTIVE, { secretValidator, secretProvider }), options);

    log(`Inviting device for identity: ${keyToString(identityKey)}` +
      ` with invitation id: ${keyToString(invitation.invitation)}`);

    return new InvitationDescriptor(InvitationDescriptorType.INTERACTIVE, invitation.swarmKey,
      invitation.invitation, identityKey);
  }

  /**
   * Redeems an invitation for this Device to be admitted to an Identity.
   * @param invitation {InvitationDescriptor}
   * @param {SecretProvider} secretProvider
   * @param {string} deviceName
   * @returns {Promise<DeviceInfo>}
   */
  // TODO(dboreham): Change deviceName to props.deviceName.
  async admitDevice (invitation, secretProvider, deviceName) {
    assert(invitation);
    assert(Buffer.isBuffer(invitation.identityKey));
    assert(secretProvider);
    assert(!this._partyManager.identityManager.hasIdentity());

    log(`Admitting device with invitation id: ${keyToString(invitation.invitation)}`);

    // TODO(telackey): Find a more elegant way to do this.
    await this._partyManager.keyRing.addPublicKey({
      type: KeyType.IDENTITY,
      publicKey: invitation.identityKey,
      own: true,
      trusted: true
    });

    const party = await this._partyManager.joinParty(invitation, secretProvider);

    // Return a promise on this event so that the await caller waits until the messages generated here
    // have been processed.
    // TODO(telackey): Add event jsdoc to this method.
    const deviceInfoWaiter = waitForEvent(this._partyManager, '@package:device:info',
      deviceInfo => deviceInfo.publicKey.equals(this.publicKey));

    // TODO(dboreham): Review whether to allow optional device name here.
    const writeFeed = await this._partyManager.getWritableFeed(party.publicKey);
    writeFeed.append(createDeviceInfoMessage(this._partyManager.keyRing, deviceName || keyToString(this.publicKey),
      this._partyManager.identityManager.deviceManager.keyRecord));

    log(`Admitted device with invitation id: ${keyToString(invitation.invitation)}`);
    return deviceInfoWaiter;
  }
}
