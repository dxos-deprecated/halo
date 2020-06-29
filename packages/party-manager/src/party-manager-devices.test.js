//
// Copyright 2020 DxOS
//

import debug from 'debug';
import waitForExpect from 'wait-for-expect';

import { Keyring, KeyType } from '@dxos/credentials';

import { TestNetworkNode } from './testing/test-network-node';
import { checkReplication, destroyNodes } from './testing/test-common';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:party-manager:test');

jest.setTimeout(100000);

const pinSecret = '0000';
const pinSecretProvider = async () => Buffer.from(pinSecret);
const pinSecretValidator = async (invitation, secret) => secret && secret.equals(invitation.secret);

const createTwoDeviceIdentity = async (props) => {
  const keyringA = new Keyring();
  await keyringA.createKeyRecord({ type: KeyType.IDENTITY });

  const nodeA = new TestNetworkNode(keyringA);
  await nodeA.initialize(props);

  const keyringB = new Keyring();
  const nodeB = new TestNetworkNode(keyringB);
  await nodeB.initialize(props);
  const nodes = [nodeA, nodeB];

  // nodeA is initialized under IdentityA as its first device.
  expect(nodeA.partyManager.identityManager.hasIdentity()).toBe(true);
  const identityKey = nodeA.partyManager.identityManager.keyRecord;

  {
    expect(nodeB.partyManager.identityManager.hasIdentity()).toBe(false);

    // Issue the invitation on nodeA.
    const invitation = await nodeA.partyManager.identityManager
      .deviceManager.addDevice(pinSecretValidator, pinSecretProvider);

    // And then redeem it on nodeB.
    const devInfo = await nodeB.partyManager.identityManager
      .deviceManager.admitDevice(invitation, pinSecretProvider, 'DeviceB');
    log(devInfo);

    expect(nodeB.partyManager.identityManager.deviceManager.displayName).toEqual('DeviceB');

    // nodeB is added to IdentityA as its second device.
    expect(nodeB.partyManager.identityManager.publicKey).toEqual(nodeA.partyManager.identityManager.publicKey);

    // Expect that nodes A, B can replicate on IdentityA's Halo.
    await checkReplication(identityKey.publicKey, nodes);
  }

  // The Identity/Device hierarchy should look like:
  //    Party (Identity):  self-signed
  //    DeviceA:  signed by Identity, DeviceA
  //    DeviceB:  signed by DeviceB, DeviceA (Greeter)
  // Both nodes should have the Identity and both Devices.
  await waitForExpect(() => {
    for (const node of nodes) {
      const halo = node.partyManager.identityManager.halo;
      const identityKey = node.partyManager.identityManager.publicKey;
      const deviceKey = node.partyManager.identityManager.deviceManager.publicKey;
      expect(halo.memberKeys.find(key => key.equals(identityKey)));
      expect(halo.memberKeys.find(key => key.equals(deviceKey)));
    }
  });

  return nodes;
};

test('Initial device authorizes additional device', async () => {
  const nodes = await createTwoDeviceIdentity();
  await destroyNodes(nodes);
});

test('Initial device authorizes device which authorizes device', async () => {
  // TODO(dboreham): Refactor to allow arbitrary number of devices.
  const nodes = await createTwoDeviceIdentity();
  await destroyNodes(nodes);
});

test('Identity having 2 devices in party with another identity having 2 devices', async () => {
  // nodeAA is initialized under IdentityA as its first device.
  // nodeAB is initialized under IdentityA as its second device.
  const nodesA = await createTwoDeviceIdentity({ identityDisplayName: 'Alice' });
  const [nodeAA] = nodesA;

  // nodeBA is initialized under IdentityB as its first device.
  // nodeBB is initialized under IdentityB as its second device.
  const nodesB = await createTwoDeviceIdentity({ identityDisplayName: 'Bob' });
  const [nodeBA] = nodesB;
  const allnodes = [...nodesA, ...nodesB];

  // nodeAA creates a Party.
  const party = await nodeAA.partyManager.createParty();

  // nodeAA invites B to the Party.
  const invitation = await nodeAA.partyManager.inviteToParty(party.publicKey, pinSecretValidator, pinSecretProvider);
  await nodeBA.partyManager.joinParty(invitation, pinSecretProvider);

  // Expect that all the nodes can now replicate with each other.
  await checkReplication(party.publicKey, allnodes);

  // Check contact info.
  await waitForExpect(async () => {
    const contactsA = await nodeAA.partyManager.getContacts();
    expect(contactsA.length).toBe(1);
    expect(contactsA[0].publicKey).toEqual(nodeBA.partyManager.identityManager.publicKey);
    expect(contactsA[0].displayName).toEqual(nodeBA.partyManager.identityManager.displayName);

    const contactsB = await nodeBA.partyManager.getContacts();
    expect(contactsB.length).toBe(1);
    expect(contactsB[0].publicKey).toEqual(nodeAA.partyManager.identityManager.publicKey);
    expect(contactsB[0].displayName).toEqual(nodeAA.partyManager.identityManager.displayName);
  });

  // Expect that nodeC identifies messages posted by nodeA and nodeB as belonging to IdentityA
  await destroyNodes(allnodes);
});

test.skip('Initial device with unauthorized device', async () => {
  // nodeA is initialized under IdentityA as its first device.
  // nodeB is initialized as un-owned.
  // Expect that nodeB can't access IdentityA's Halo, even if it knows IdentityA's public key.
  // nodeA creates and joins a new Party.
  // Expect that nodeB can not access that Party.
});

test.skip('New device added to identity after joining party with another identity', async () => {
  // nodeA is initialized under IdentityA as its first device.
  // nodeB is initialized under IdentityB as its first device.
  // nodeA creates a Party.
  // nodeA invites clientC to the Party.
  // nodeB redeems the invitation.
  // Expect that nodes A, B can replicate on the Party.
  // Expect that each client identifies messages by the proper Identity.
  // clientC is initialized under IdentityA as its second device.
  // Expect that nodes A, B, C can replicate on the Party.
  // Expect that each client identifies messages by the proper Identity.
  // clientD is initialized under IdentityB as its second device.
  // Expect that nodes A, B, C, D can replicate on the Party.
  // Expect that each client identifies messages by the proper Identity.
});

// TODO(dboreham): additional tests:
// Revoke device.
// Two devices in party with a bot.
