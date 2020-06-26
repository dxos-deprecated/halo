//
// Copyright 2020 DxOS
//

import debug from 'debug';

import { sleep } from '@dxos/async';
import { Keyring, KeyType, generateSeedPhrase, keyPairFromSeedPhrase } from '@dxos/credentials';
import { keyToString } from '@dxos/crypto';

import { TestNetworkNode } from './testing/test-network-node';

const log = debug('dxos:party-manager:test');

test('Create initial node with new Identity', async (done) => {
  // Create empty keyring and node objects (FeedStore, PartyManager, NetworkProvider).
  const keyring = new Keyring();
  const node = new TestNetworkNode(keyring);
  await node.initialize();
  log('Node initialized');

  // Generate seed phrase and load key pair into keyring.
  const seedPhrase = generateSeedPhrase();
  log('Seed phrase:', seedPhrase);
  const identityKeyPair = keyPairFromSeedPhrase(seedPhrase);
  log('Identity Public Key:', keyToString(identityKeyPair.publicKey));
  await keyring.addKeyRecord({ ...identityKeyPair, type: KeyType.IDENTITY });
  // Set Identity display name and initial device display name.
  const identityDisplayName = 'Identity 1';
  const deviceDisplayName = 'Device 1';

  await node.partyManager.identityManager.initializeForNewIdentity({ identityDisplayName, deviceDisplayName });
  log('Identity initialized');

  // TODO(dboreham): How do we know when system has Quiesced? (this is probably why we use waitForExpect()).
  // Temporary hack, sleep for a while:
  await sleep(500);

  // Check key and displayName are correct via IdentityManager
  const identityManager = node.partyManager.identityManager;
  const readIdentityDisplayName = identityManager.displayName;
  expect(readIdentityDisplayName).toBeDefined();
  expect(readIdentityDisplayName).toEqual(identityDisplayName);
  const readIdentityKey = identityManager.publicKey;
  expect(readIdentityKey).toEqual(identityKeyPair.publicKey);
  const readDevices = identityManager.deviceManager.devices;
  expect(readDevices).toBeDefined();
  expect(readDevices).toHaveLength(1);
  const device = readDevices[0];
  expect(device).toHaveProperty('displayName');
  expect(device.displayName).toEqual(deviceDisplayName);

  await node.destroy();
  done();
});
