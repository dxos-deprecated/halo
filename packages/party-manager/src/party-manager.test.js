//
// Copyright 2020 DxOS
//

import debug from 'debug';
import ram from 'random-access-memory';
import bufferJson from 'buffer-json-encoding';
import waitForExpect from 'wait-for-expect';

import { Filter, Keyring, KeyType } from '@dxos/credentials';
import { FeedStore } from '@dxos/feed-store';
import { NetworkManager, SwarmProvider } from '@dxos/network-manager';

import { PartyManager } from './party-manager';

const log = debug('dxos:party-manager:test');

jest.setTimeout(10000);

// TODO(dboreham): test not complete
test('Create a PartyManager with an Identity', async () => {
  const keyRing = new Keyring();

  const feedStore = await FeedStore.create(ram, {
    feedOptions: { valueEncoding: 'buffer-json' },
    codecs: { 'buffer-json': bufferJson }
  });
  const swarmProvider = new SwarmProvider();
  const networkManager = new NetworkManager(feedStore, swarmProvider);
  const identityKey = await keyRing.createKeyRecord({ type: KeyType.IDENTITY });

  log('Creating PartyManager');
  const partyManager = new PartyManager(feedStore, keyRing, networkManager);
  await partyManager.initialize();
  log('Created PartyManager');
  expect(partyManager.identityManager.hasIdentity()).toBe(true);

  log('Creating Identity Hub');
  const hub = await partyManager.identityManager.initializeForNewIdentity();
  log('Created Identity Hub');
  expect(hub).toBeTruthy();

  const deviceKey = keyRing.findKey(Filter.matches({ type: KeyType.DEVICE }));

  await waitForExpect(() => {
    expect(hub.publicKey).toEqual(identityKey.publicKey);
    expect(hub.memberKeys.length).toBe(2);
    expect(hub.memberKeys).toContainEqual(identityKey.publicKey);
    expect(hub.memberKeys).toContainEqual(deviceKey.publicKey);
  });

  const party = await partyManager.createParty();
  expect(party).toBeTruthy();

  await waitForExpect(() => {
    expect(party.memberKeys.length).toBe(2);
    expect(party.memberKeys).toContainEqual(identityKey.publicKey);
    // expect(party.memberKeys).not.toContainEqual(deviceKey.publicKey);
  });

  log('Created PartyManager');
});
