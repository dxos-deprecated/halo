//
// Copyright 2019 DxOS
//

import assert from 'assert';

import { createId, randomBytes } from '@dxos/crypto';

import { createDateTimeString } from '../proto/datetime';

/**
 * Represents a single-use invitation to admit the Invitee to the Party.
 * During Greeting the invitation will cross through the states:
 *
 *   1. issued
 *   2. presented
 *   3. negotiated
 *   4. submitted
 *   5. finished
 *
 * It may also be revoked at anytime.
 */
export class Invitation {
  /**
   * @param {Buffer} partyKey
   * @param {SecretValidator} secretValidator
   * @param {SecretProvider} [secretProvider]
   * @param {function} [onFinish]
   * @param {int} [expiration]
   */
  // TODO(burdon): JsDoc options.
  constructor (partyKey, secretValidator, secretProvider, onFinish = () => {
  }, expiration = 0) {
    assert(Buffer.isBuffer(partyKey));

    this._partyKey = partyKey;
    this._secretValidator = secretValidator;
    this._secretProvider = secretProvider;
    this._onFinish = onFinish;
    this._expiration = expiration;

    this._id = createId();
    this._nonce = randomBytes(32);
    this._secret = null;

    // TODO(telackey): Change to InvitationState.

    this._issued = createDateTimeString();
    this._presented = null;
    this._negotiated = null;
    this._submitted = null;
    this._finished = null;
    this._revoked = null;
  }

  get id () {
    return this._id;
  }

  get nonce () {
    return this._nonce;
  }

  get partyKey () {
    return this._partyKey;
  }

  get live () {
    return !this.finished && !this.expired && !this.revoked;
  }

  get presented () {
    return !!this._presented;
  }

  get submitted () {
    return !!this._submitted;
  }

  get negotiated () {
    return !!this._negotiated;
  }

  get revoked () {
    return !!this._revoked;
  }

  get finished () {
    return !!this._finished;
  }

  get expired () {
    if (this._expiration) {
      return createDateTimeString() >= this._expiration;
    }
    return false;
  }

  get secret () {
    return this._secret;
  }

  /**
   * Revokes the invitation.
   * @returns {Promise<boolean>} true if the invitation was alive, else false
   */
  async revoke () {
    if (!this.live) {
      return false;
    }

    this._revoked = createDateTimeString();

    return true;
  }

  /**
   * Handles invitation presentation (ie, triggers the secretProvider) and
   * marks the invitation as having been presented.
   * @returns {Promise<boolean>} true if the invitation was alive, else false
   */
  async present () {
    if (!this.live) {
      return false;
    }

    if (!this._secret && this._secretProvider) {
      this._secret = await this._secretProvider(this);
    }

    this._presented = createDateTimeString();

    return true;
  }

  /**
   * Marks the invitation as having been negotiated.
   * @returns {Promise<boolean>} true if the invitation was alive, else false
   */
  async negotiate () {
    if (!this.live) {
      return false;
    }

    this._negotiated = createDateTimeString();

    return true;
  }

  /**
   * Marks the invitation as having been submitted.
   * @returns {Promise<boolean>} true if the invitation was alive, else false
   */
  async submit () {
    if (!this.live) {
      return false;
    }

    this._submitted = createDateTimeString();

    return true;
  }

  /**
   * Marks the invitation as having been finished and triggers any
   * onFinish handlers if present.
   * @returns {Promise<boolean>} true if the invitation was alive, else false
   */
  async finish () {
    if (!this.live) {
      return false;
    }

    this._finished = createDateTimeString();
    if (this._onFinish) {
      await this._onFinish();
    }

    return true;
  }

  /**
   * Returns `true` if the invitation and secret are valid, else `false`.
   * @param {*} secret
   * @returns {Promise<boolean>}
   */
  async validate (secret) {
    return this._secretValidator(this, secret);
  }
}
