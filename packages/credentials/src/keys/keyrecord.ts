
//
// Copyright 2020 DXOS.org
//

import { PublicKey } from '@dxos/crypto';

import { Key } from '../proto';

export interface KeyRecord extends Omit<Key, 'publicKey' | 'secretKey'> {
  publicKey: PublicKey,
  secretKey?: Buffer
}
