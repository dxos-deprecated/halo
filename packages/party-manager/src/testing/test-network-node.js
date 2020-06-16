//
// Copyright 2020 DxOS
//

import assert from 'assert';
import bufferJson from 'buffer-json-encoding';
import debug from 'debug';
import ram from 'random-access-memory';

import { FeedStore } from '@dxos/feed-store';
import { NetworkManager, SwarmProvider } from '@dxos/network-manager';

import { PartyManager } from '../party-manager';
import { TestModelFactory } from './test-model-factory';

const log = debug('dxos:party-manager:test:node');

/**
 * Provides similar, but minimally functional capabilities to @dxos/data-client/client.js,
 * for testing party-manager in vitro without circular dependency on data-client.
 */
export class TestNetworkNode {
  /** @type {FeedStore} */
  _feedStore;

  /** @type {Keyring} */
  keyRing;

  /** @type {TestModelFactory} */
  modelFactory;

  /** @type {NetworkManager} */
  _networkManager;

  /** @type {PartyManager} */
  partyManager;

  /** @type {SwarmProvider} */
  _swarmProvider;

  /**
   * @param {Keyring} keyRing
   */
  constructor (keyRing) {
    assert(keyRing);
    this.keyRing = keyRing;
  }

  async initialize (props = {}) {
    this._feedStore = await FeedStore.create(ram, {
      feedOptions: {
        // Required by party messages/greet message encoding, needs to be changed when protobuf codecs are enabled.
        valueEncoding: 'buffer-json'
      },
      codecs: {
        'buffer-json': bufferJson
      }
    });
    log('Created FeedStore');
    this._swarmProvider = new SwarmProvider();
    this._networkManager = new NetworkManager(this._feedStore, this._swarmProvider);
    this.partyManager = new PartyManager(this._feedStore, this.keyRing, this._networkManager);
    this.modelFactory = new TestModelFactory(this._feedStore,
      partyKey => this.partyManager.getWritableStream(partyKey));

    await this.partyManager.initialize();
    log('Initialized PartyManager');
    if (this.partyManager.identityManager.hasIdentity()) {
      const hasHalo = await this.partyManager.identityManager.isInitialized();
      if (!hasHalo) {
        await this.partyManager.identityManager.initializeForNewIdentity(props);
        log('Initialized IdentityManager');
      }
    }
  }

  async destroy () {
    log('Destroying');
    await this.partyManager.destroy();
    await this._networkManager.close();
    await this._feedStore.close();
    log('Destroyed');
  }
}
