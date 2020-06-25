//
// Copyright 2019 DxOS
//

import debug from 'debug';
import waitForExpect from 'wait-for-expect';

import { Keyring, KeyType } from '@dxos/credentials';
import { createKeyPair, randomBytes, sign, verify, SIGNATURE_LENGTH } from '@dxos/crypto';

import { TestNetworkNode } from './testing/test-network-node';
import { checkReplication, checkPartyInfo, createTestParty, destroyNodes } from './testing/test-common';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:party-manager:test');

test('Create a party with 2 Identities each having one device (signature invitation)', async () => {
  const keyringA = new Keyring();
  await keyringA.createKeyRecord({ type: KeyType.IDENTITY });
  const keyringB = new Keyring();
  await keyringB.createKeyRecord({ type: KeyType.IDENTITY });

  const nodeA = new TestNetworkNode(keyringA);
  await nodeA.initialize({ identityDisplayName: 'IdentityA', deviceDisplayName: 'Device1-A' });
  const nodeB = new TestNetworkNode(keyringB);
  await nodeB.initialize({ identityDisplayName: 'IdentityB', deviceDisplayName: 'Device1-B' });
  const nodes = [nodeA, nodeB];

  // Create the Party.
  const party = await nodeA.partyManager.createParty();

  // In real life this would be a keypair associated with BotFactory.
  const keyPair = createKeyPair();

  // Provided by Greeter initiator.
  const greeterSecretValidator = async (invitation, secret) => {
    const signature = secret.slice(0, SIGNATURE_LENGTH);
    const message = secret.slice(SIGNATURE_LENGTH);
    return verify(message, signature, keyPair.publicKey);
  };

  // Issue the invitation on nodeA.
  const invitationDescriptor = await nodeA.partyManager.inviteToParty(party.publicKey, greeterSecretValidator);

  // The `secret` Buffer is composed of the signature (fixed length) followed by the message (variable length).
  const inviteeSecretProvider = async () => {
    const message = randomBytes(32);
    const signature = sign(message, keyPair.secretKey);
    const secret = Buffer.alloc(signature.length + message.length);
    signature.copy(secret);
    message.copy(secret, signature.length);
    return secret;
  };

  // And then redeem it on nodeB.
  await nodeB.partyManager.joinParty(invitationDescriptor, inviteeSecretProvider);

  await checkReplication(party.publicKey, nodes);
  await checkPartyInfo(party.publicKey, nodes);
  await destroyNodes(nodes);
});

test('Create a party with 3 identities each having one device (secret invitation)', async () => {
  const { party, nodes } = await createTestParty(3);
  await checkReplication(party.publicKey, nodes);
  await checkPartyInfo(party.publicKey, nodes);
  await destroyNodes(nodes);
});

test('Check subscribe/unsubscribe', async (done) => {
  const { party: { publicKey: partyKey }, nodes } = await createTestParty(3);
  await checkReplication(partyKey, nodes);
  await checkPartyInfo(partyKey, nodes);

  const [nodeA, nodeB, nodeC] = nodes;
  await nodeA.partyManager.unsubscribe(partyKey);
  await waitForExpect(() => {
    const party = nodeA.partyManager.getParty(partyKey);
    expect(party.isOpen()).toBe(false);
  }, 1000);

  // Replication should keep working between B and C.
  await checkReplication(partyKey, [nodeB, nodeC]);

  // It should not work to and from A.
  try {
    await checkReplication(partyKey, nodes);
    done.fail();
  } catch (err) {
    expect(err).toBeInstanceOf(Error);
  }

  // Re-subscribe.
  await nodeA.partyManager.subscribe(partyKey);

  // Now it should work again.
  await waitForExpect(() => {
    const party = nodeA.partyManager.getParty(partyKey);
    expect(party.isOpen()).toBe(true);
  }, 1000);
  await checkReplication(partyKey, nodes);

  await destroyNodes(nodes);
  done();
});
