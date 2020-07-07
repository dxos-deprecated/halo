//
// Copyright 2020 DXOS.org
//

import assert from 'assert';

import { noop } from '@dxos/async';

export const InviteType = Object.freeze({
  INTERACTIVE: '1',
  OFFLINE_KEY: '2'
});

export class InviteDetails {
  constructor (type, { secretValidator = noop, secretProvider = noop, publicKey = null }) {
    assert(type);
    if (InviteType.INTERACTIVE === type) {
      assert(secretValidator);
      assert(secretProvider);
    } else if (InviteType.OFFLINE_KEY === type) {
      assert(Buffer.isBuffer(publicKey));
    }

    this._type = type;
    this._secretValidator = secretValidator;
    this._secretProvider = secretProvider;
    this._publicKey = publicKey;
  }

  get type () {
    return this._type;
  }

  get secretValidator () {
    return this._secretValidator;
  }

  get secretProvider () {
    return this._secretProvider;
  }

  get publicKey () {
    return this._publicKey;
  }
}
