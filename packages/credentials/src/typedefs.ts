//
// Copyright 2019 DXOS.org
//

import { PublicKey } from '@dxos/crypto';

import { KeyType } from './keys';

export type MakeOptional<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>> & Partial<Pick<T, K>>;

export type RawSignature = Uint8Array;

export type SecretKey = Buffer;
export type DiscoveryKey = Buffer;
export type PeerId = Buffer;

// TODO(marik-d): Use protobuf type.
export interface KeyRecord {
    /**
     * - The `KeyType` type of the key. This is often unknown for keys from other sources.
     */
    type: KeyType;
    /**
     * - The public key as a hex string.
     */
    key: string;
    /**
     * - The public key as a Buffer (required).
     */
    publicKey: PublicKey;
    /**
     * - The secret key as a Buffer (this will never be visible outside the Keyring).
     */
    secretKey?: SecretKey;
    /**
     * - Is this key from a Greeting "hint"?
     */
    hint?: boolean;
    /**
     * - Is this our key? Usually true if `secretKey` is present,
     *          may be false for "inception keys" such as the Party key.
     */
    own?: boolean;
    /**
     * - Is this key to be trusted?
     */
    trusted?: boolean;
    /**
     * - An RFC-3339 date/time string for when the key was added to the Keyring.
     */
    added?: string;
    /**
     * - An RFC-3339 date/time string for when the key was created.
     */
    created?: string;
}
