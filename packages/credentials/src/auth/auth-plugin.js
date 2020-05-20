//
// Copyright 2019 DxOS
//

import assert from 'assert';
import debug from 'debug';
import { EventEmitter } from 'events';

import { Extension, ERR_EXTENSION_RESPONSE_FAILED } from '@dxos/protocol';
import { keyToString } from '@dxos/crypto';

import { ERR_AUTH_GENERAL, ERR_AUTH_REJECTED } from './error-codes';
import { codec } from '../proto';

const log = debug('dxos:creds:auth');

const EXTENSION_NAME = 'auth';

/**
 * A Protocol extension to require nodes to be authenticated during handshake before being allowed to replicate.
 *
 * Authentication success event
 * @event AuthPlugin#authenticated
 * @type {Buffer} peerId
 */
export class AuthPlugin extends EventEmitter {
  /**
   * @constructor
   * @param {Buffer} peerId
   * @param {AuthenticatorDialog} authenticator
   */
  constructor (peerId, authenticator) {
    assert(Buffer.isBuffer(peerId));
    assert(authenticator);
    super();

    // TODO(burdon): Not used.
    this._peerId = peerId;
    this._authenticator = authenticator;
  }

  get authenticator () {
    return this._authenticator;
  }

  /**
   * Create protocol extension.
   * @return {Extension}
   */
  createExtension () {
    return new Extension(EXTENSION_NAME, { binary: true }).setHandshakeHandler(this._onHandshake.bind(this));
  }

  /**
   * Handler to be called when the 'handshake' event is emitted.
   * If the session can not be authenticated, a ERR_EXTENSION_RESPONSE_FAILED will be thrown.
   * @param protocol
   * @returns {Promise<void>}
   * @private
   * @fires AuthPlugin#authenticated
   */
  // TODO(dboreham): Improve Protocol to avoid this:
  // Below, the pattern throw(ERR_EXTENSION_RESPONSE_FAILED(<details>) is used in place of
  // simply sending a response to the peer's authentication request.
  // This is done because there is no known way using the current lower layer
  // implementation (Protocol, dependencies) to explicitly send such a response message.
  // TODO(telackey): supply further background/detail and correct anything incorrect above.
  _onHandshake = async (protocol /* , context */) => { // TODO(burdon): ???
    assert(protocol);

    // Obtain the credentials from the session.
    // At this point credentials is protobuf encoded and base64-encoded
    // Note protocol.session.credentials is our data
    const { credentials } = protocol && protocol.getSession() ? protocol.getSession() : {};
    if (!credentials) {
      protocol.stream.destroy();
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_AUTH_REJECTED, 'Authentication rejected: no credentials.');
    }

    let wrappedCredentials;
    try {
      // TODO(dboreham): credentials is a base64-encoded string. Determine if that's the type we expect
      // TODO(dboreham): should have assert(isString(credentials)) ?
      wrappedCredentials = codec.decode(Buffer.from(credentials, 'base64'));
    } catch (err) {
      protocol.stream.destroy();
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_AUTH_GENERAL, err);
    }

    // Unwrap from root message.
    const { payload } = wrappedCredentials;

    // The peerId in the normal session info should match that in the signed credentials.
    const { peerId: sessionPeerId } = protocol.getSession();
    const { payload: { deviceKey: credsPeerId } } = payload.signed || {};
    if (!sessionPeerId || !credsPeerId || keyToString(sessionPeerId) !== keyToString(credsPeerId)) {
      protocol.stream.destroy();
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_AUTH_REJECTED, 'Authentication rejected: bad peerId.');
    }

    // TODO(telackey): The signed credentials ought to contain verifiable information for both ends, eg,
    // the ID of both source and target, and a nonce or challenge provided by the target to the source
    // for this particular exchange. We will need to add appropriate hooks between the connect and
    // handshake calls to do that though.

    // Ask the Authenticator if this checks out.
    const authenticated = await this._authenticator.authenticate(payload);
    if (!authenticated) {
      protocol.stream.destroy();
      throw new ERR_EXTENSION_RESPONSE_FAILED(ERR_AUTH_REJECTED, 'Authentication rejected: bad credentials.');
    }

    // Success!
    log(`Authenticated peer: ${keyToString(credsPeerId)}`);
    // TODO(dboreham): should this be a callback rather than an event, or communicated some other way to
    //   code that needs to know about auth success events?
    this.emit('authenticated', credsPeerId);
  };
}
