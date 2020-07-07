//
// Copyright 2020 DxOS
//

import assert from 'assert';
import stableStringify from 'json-stable-stringify';

import { keyToBuffer, keyToString } from '@dxos/crypto';

import { ripemd160 } from './util';

// TODO(telackey): Add comment explaining in brief what is going on.
//  e.g. what is hash for?
//  e.g. do we expect users of this class to serialize it themselves?

export const InvitationDescriptorType = Object.freeze({
  INTERACTIVE: '1',
  PARTY: '2'
});

// TODO(telackey): Add class description:
/**
 * Description of what this class is for goes here.
 */
export class InvitationDescriptor {
  /**
   * Reconstructs an InvitationDescriptor from query parameters.
   * @param {Object} queryParameters
   * @property {string} query.hash
   * @property {string} query.swarmKey
   * @property {string} query.invitation
   * @property {string} query.identityKey
   * @property {string} query.type
   * @returns {InvitationDescriptor}
   */
  static fromQueryParameters (queryParameters) {
    const { hash, swarmKey, invitation, identityKey, type } = queryParameters;

    const descriptor = new InvitationDescriptor(type, keyToBuffer(swarmKey),
      keyToBuffer(invitation), (identityKey) ? keyToBuffer(identityKey) : undefined);

    if (hash !== descriptor.hash) {
      throw new Error('Invalid hash.');
    }

    return descriptor;
  }

  // TODO(dboreham): Switch back to private member variables since we have encapsulated this class everywhere.
  /** @type {Buffer} */
  swarmKey;

  /** @type {Buffer} */
  invitation;

  /** @type {Buffer} */
  identityKey;

  /**
   * @param {Buffer} swarmKey
   * @param {Buffer} invitation
   * @param {Buffer} [identityKey]
   */
  constructor (type, swarmKey, invitation, identityKey) {
    assert(type);
    assert(Buffer.isBuffer(swarmKey));
    assert(Buffer.isBuffer(invitation));
    if (identityKey) {
      assert(Buffer.isBuffer(identityKey));
    }

    this.type = type;
    this.swarmKey = swarmKey;
    this.invitation = invitation;
    this.identityKey = identityKey;
  }

  get hash () {
    const query = this.toQueryParameters();
    return query.hash;
  }

  /**
   * Exports an InvitationDescriptor to an object suitable for use as query parameters.
   * @returns {object}
   */
  toQueryParameters () {
    const query = {
      swarmKey: keyToString(this.swarmKey),
      invitation: keyToString(this.invitation),
      type: this.type
    };

    if (this.identityKey) {
      query.identityKey = keyToString(this.identityKey);
    }

    query.hash = ripemd160(stableStringify(query));

    return query;
  }
}
