//
// Copyright 2019 DXOS.org
//

export type PublicKey = Buffer;
export type SecretKey = Buffer;

export interface KeyChain {
    publicKey: PublicKey;
    message: Message | SignedMessage;
    parents: KeyChain[];
}

export interface KeyRecord {
    /**
     * - The `KeyType` type of the key. This is often unknown for keys from other sources.
     */
    type: string;
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

export interface Message {
    __type_url: string; // eslint-disable-line camelcase
    payload: any;
}

export interface Signed {
    created: string;
    nonce: Buffer;
    payload: object;
}

export interface Signature {
    key: PublicKey;
    signatures: Buffer[];
    keyChain?: KeyChain;
}

export interface SignedMessage {
    signed: Signed;
    signatures: Signature[];
}

export interface AuthMessage {
  partyKey: PublicKey
  identetyKey: PublicKey
  deviceKey: PublicKey
}

export type LevelDB = any;
export type LevelDB_Factory = (topic: string) => LevelDB; // eslint-disable-line camelcase
