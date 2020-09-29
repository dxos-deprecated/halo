//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import get from 'lodash.get';

import { randomBytes } from '@dxos/crypto';

import { codec } from '../proto';

/**
 * Constants
 */
// TODO(burdon): Use generated classes.
export const PartyCredential = {
  Type: Object.freeze({
    ...codec.getType('dxos.credentials.party.PartyCredential.Type').values
  })
};

// TODO(dboreham): Temporary
// This needs to be done with a model filter that allows reaching into the signed message
// to determine the signed payload message type.
// Define current model type here to remove multiple definitions in various other places
export const partyModelType = () => 'dxos.credentials.Message';

/**
 * The start-of-authority record for the Party, admitting a single key (usually a identity) and a single feed.
 * It must be signed by all three keys (party, key, feed). The Party private key should be destroyed after
 * signing this message.
 * @param {Keyring} keyring
 * @param {KeyRecord} partyKeyPair
 * @param {KeyRecord} feedKeyPair
 * @param {KeyRecord} admitKeyPair
 * @returns {SignedMessage}
 */
export const createPartyGenesisMessage = (keyring, partyKeyPair, feedKeyPair, admitKeyPair) => {
  assert(keyring);
  assert(partyKeyPair);
  assert(feedKeyPair);
  assert(admitKeyPair);
  assert(keyring.hasSecretKey(admitKeyPair));
  assert(typeof admitKeyPair.type !== 'undefined');

  const message = {
    __type_url: 'dxos.credentials.party.PartyCredential',
    type: PartyCredential.Type.PARTY_GENESIS,
    contents: {
      __type_url: 'dxos.credentials.party.PartyGenesis',
      partyKey: partyKeyPair.publicKey,
      feedKey: feedKeyPair.publicKey,
      admitKey: admitKeyPair.publicKey,
      admitKeyType: admitKeyPair.type
    }
  };

  // TODO(burdon): Use any from codec-protobuf.
  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [partyKeyPair, feedKeyPair, admitKeyPair])
  };
};

/**
 * Admit a single key to the Party. This message must be signed by the key to be admitted, and unless the contents
 * of an Envelope, also by a key which has already been admitted.
 * @param {Keyring} keyring
 * @param {Buffer} partyKey
 * @param {KeyRecord} admitKeyPair
 * @param {KeyRecord[]} signingKeys
 * @param {Buffer} [nonce]
 * @returns {SignedMessage}
 */
export const createKeyAdmitMessage = (keyring, partyKey, admitKeyPair, signingKeys = [], nonce = null) => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(admitKeyPair);
  assert(keyring.hasSecretKey(admitKeyPair));
  assert(typeof admitKeyPair.type !== 'undefined');
  assert(Array.isArray(signingKeys) || signingKeys);

  if (!Array.isArray(signingKeys)) {
    signingKeys = [signingKeys];
  }

  const message = {
    __type_url: 'dxos.credentials.party.PartyCredential',
    type: PartyCredential.Type.KEY_ADMIT,
    contents: {
      __type_url: 'dxos.credentials.party.KeyAdmit',
      partyKey,
      admitKey: admitKeyPair.publicKey,
      admitKeyType: admitKeyPair.type
    }
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [admitKeyPair, ...signingKeys], nonce)
  };
};

/**
 * Admit a single feed to the Party. This message must be signed by the feed key to be admitted, also by some other
 * key which has already been admitted (usually by a device identity key).
 * @param {Keyring} keyring
 * @param {Buffer} partyKey
 * @param {KeyRecord} feedKeyPair
 * @param {KeyRecord[]} signingKeys
 * @param {Buffer} [nonce]
 * @returns {SignedMessage}
 */
export const createFeedAdmitMessage = (keyring, partyKey, feedKeyPair, signingKeys = [], nonce = null) => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(feedKeyPair);
  assert(Array.isArray(signingKeys) || signingKeys);

  if (!Array.isArray(signingKeys)) {
    signingKeys = [signingKeys];
  }

  const message = {
    __type_url: 'dxos.credentials.party.PartyCredential',
    type: PartyCredential.Type.FEED_ADMIT,
    contents: {
      __type_url: 'dxos.credentials.party.FeedAdmit',
      partyKey,
      feedKey: feedKeyPair.publicKey
    }
  };

  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [feedKeyPair, ...signingKeys], nonce)
  };
};

/**
 * A signed message containing a signed message. This is used by a Greeter to write, and sign using its key, a
 * message provided to it, signed by the Invitee to the Party. The signature on the Envelope is that of the Greeter,
 * while the signature(s) on the interior message are those of the Invitee, demonstrating ownership by the Invitee
 * of the keys or feeds to be admitted. The interior message can only be of types:
 *   KEY_ADMIT
 *   FEED_ADMIT
 * Any other message type (eg, PARTY_GENESIS) is invalid and must be rejected.
 * @param keyring
 * @param partyKey
 * @param contents
 * @param signingKeys
 * @returns {SignedMessage}
 */
// TODO(burdon): What is an envelope, distinct from above?
export const createEnvelopeMessage = (keyring, partyKey, contents, signingKeys = [], nonce) => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(contents);
  assert(Array.isArray(signingKeys) || signingKeys);
  if (!Array.isArray(signingKeys)) {
    signingKeys = [signingKeys];
  }

  // The contents are always a Message.
  if (contents.__type_url !== 'dxos.credentials.Message') {
    contents = {
      __type_url: 'dxos.credentials.Message',
      payload: contents
    };
  }

  const message = {
    __type_url: 'dxos.credentials.party.PartyCredential',
    type: PartyCredential.Type.ENVELOPE,
    contents: {
      __type_url: 'dxos.credentials.party.Envelope',
      partyKey,
      contents
    }
  };

  // TODO(burdon): This probably shouldn't be wrapped in a Message.
  return {
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign(message, [...signingKeys], nonce) // TODO(burdon): Why copy the array? (Above too).
  };
};

/**
 * Is `message` a PartyCredential message?
 * @param {Message} message
 * @return {boolean}
 */
export const isPartyCredentialMessage = (message) => {
  const payloadType = get(message, 'payload.__type_url');
  const signedType = get(message, 'payload.signed.payload.__type_url');
  return payloadType === 'dxos.credentials.SignedMessage' &&
    signedType === 'dxos.credentials.party.PartyCredential';
};

/**
 * Is SignedMessage `message` an Envelope?
 * @param {SignedMessage} message
 * @return {boolean}
 * @private
 */
export const isEnvelope = (message) => {
  assert(message);
  // TODO: Test it is a PartyCredential
  const { signed: { payload: { type } = {} } = {} } = message;
  return type === PartyCredential.Type.ENVELOPE;
};

/**
 * Is this a SignedMessage?
 * @param {Object} message
 * @return {boolean}
 * @private
 */
export const isSignedMessage = (message) => {
  return message && message.signed && message.signed.payload && message.signatures && Array.isArray(message.signatures);
};

/**
 * Unwrap a SignedMessage from its Envelopes.
 * @param {SignedMessage} message
 * @return {SignedMessage} message
 */
export const unwrapEnvelopes = (message) => {
  // Unwrap any Envelopes
  while (isEnvelope(message)) {
    message = message.signed.payload.contents.contents.payload;
  }
  return message;
};

/**
 * Extract the contents of a SignedMessage
 * @param {SignedMessage} message
 * @return {Message} message
 */
export const extractContents = (message) => {
  // Unwrap any payload.
  while (message.signed || message.payload) {
    message = message.signed || message.payload;
  }
  return message;
};

/**
 * Returns the PartyCredential.Type for the message.
 * @param {SignedMessage} message
 * @param {boolean} [deep=true] Whether to return the inner type of a message if it is in an ENVELOPE.
 */
export const getPartyCredentialMessageType = (message, deep = true) => {
  message = message.signed && message.signatures ? message : message.payload;
  const { signed: { payload: { type } = {} } = {} } = message || {};
  if (deep && type === PartyCredential.Type.ENVELOPE) {
    return getPartyCredentialMessageType(message.signed.payload.contents.contents.payload);
  }
  return type;
};

/**
 * Provides a list of the publicKeys admitted by this PartyCredentialMessage.
 * @param {Message|SignedMessage} message
 * @return {Buffer[]}
 */
export const admitsKeys = (message) => {
  assert(message);
  assert(isPartyCredentialMessage(message));

  const keys = [];

  if (!message.signed && message.payload) {
    message = message.payload;
  }

  while (isEnvelope(message)) {
    message = message.signed.payload.contents.contents.payload;
  }

  const type = getPartyCredentialMessageType(message, false);
  const { admitKey, feedKey, partyKey } = message.signed.payload.contents;
  switch (type) {
    case PartyCredential.Type.PARTY_GENESIS:
      keys.push(partyKey);
      keys.push(admitKey);
      keys.push(feedKey);
      break;
    case PartyCredential.Type.KEY_ADMIT:
      keys.push(admitKey);
      break;
    case PartyCredential.Type.FEED_ADMIT:
      keys.push(feedKey);
      break;
    default:
      throw Error(`Invalid type: ${type}`);
  }

  return keys;
};

/**
 * Create a `dxos.credentials.party.PartyInvitation` message.
 * @param {Keyring} keyring
 * @param {PublicKey} partyKey
 * @param {PublicKey} inviteeKey
 * @param {KeyRecord|KeyChain} issuerKey
 * @param {KeyRecord|KeyChain} [signingKey]
 * @returns {Message}
 */
export const createPartyInvitationMessage = (keyring, partyKey, inviteeKey, issuerKey, signingKey) => {
  assert(keyring);
  assert(Buffer.isBuffer(partyKey));
  assert(Buffer.isBuffer(inviteeKey));
  assert(Buffer.isBuffer(issuerKey.publicKey));
  if (!signingKey) {
    signingKey = issuerKey;
  }
  assert(Buffer.isBuffer(signingKey.publicKey));
  assert(keyring.hasSecretKey(signingKey));

  return {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.party.PartyInvitation',
        id: randomBytes(),
        partyKey,
        issuerKey: issuerKey.publicKey,
        inviteeKey: inviteeKey
      }, [signingKey])
  };
};

/**
 * Is `message` a PartyInvitation message?
 * @param {Message} message
 * @return {boolean}
 */
export const isPartyInvitationMessage = (message) => {
  if (message.payload && !message.signed) {
    message = message.payload;
  }

  const payloadType = get(message, '__type_url');
  const signedType = get(message, 'signed.payload.__type_url');
  return payloadType === 'dxos.credentials.SignedMessage' &&
    signedType === 'dxos.credentials.party.PartyInvitation';
};
