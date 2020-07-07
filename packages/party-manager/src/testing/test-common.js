//
// Copyright 2020 DxOS
//

import waitForExpect from 'wait-for-expect';

import { createId, keyToString } from '@dxos/crypto';
import { Keyring, KeyType } from '@dxos/credentials';

import { InviteDetails, InviteType } from '../invite-details';
import { TestModel } from './test-model';
import { TestNetworkNode } from './test-network-node';

/**
 * Writes a message on each node and looks for that message on all the others.
 */
export const checkReplication = async (partyKey, nodes) => {
  const MODEL_TYPE = 'testing.Test';
  const topic = keyToString(partyKey);
  const models = [];
  const values = [];

  for await (const node of nodes) {
    await waitForExpect(() => {
      const party = node.partyManager.getParty(partyKey);
      expect(party).toBeTruthy();
    });
  }

  // Write a message on each node.
  for await (const node of nodes) {
    const model = await node.modelFactory.createModel(TestModel, { type: MODEL_TYPE, topic });
    const value = createId();

    await model.appendMessage({ __type_url: MODEL_TYPE, value });
    models.push(model);
    values.push(value);
  }

  // And then check that each one has every message.
  try {
    for await (const model of models) {
      await waitForExpect(() => {
        const messages = model.messages.map(message => message.value);
        for (const value of values) {
          expect(messages).toContain(value);
        }
      }, 2000);
    }
  } finally {
    for await (const model of models) {
      // TODO(dboreham): This call isn't async which seems odd: how do we know it is closed?
      model.destroy();
    }
  }
};

/**
 * Makes sure the PartyInfo matches what is expected across all nodes.
 */
export const checkPartyInfo = async (partyKey, nodes) => {
  for await (const node of nodes) {
    await waitForExpect(() => {
      const partyInfo = node.partyManager.getPartyInfo(partyKey);
      expect(partyInfo.publicKey).toEqual(partyKey);
      expect(partyInfo.members.length).toBe(nodes.length);
      const me =
        partyInfo.members.find(member => member.publicKey.equals(node.partyManager.identityManager.publicKey));
      expect(me.isMe).toBe(true);
      expect(me.feeds.length).toBe(node.partyManager.identityManager.deviceManager.devices.length);
      expect(me.displayName).toEqual(node.partyManager.identityManager.displayName);
      for (const other of nodes) {
        if (other !== node) {
          const them =
            partyInfo.members.find(member => member.publicKey.equals(other.partyManager.identityManager.publicKey));
          expect(them).toBeTruthy();
          expect(them.admittedBy).toBeTruthy();
          expect(them.isMe).toBe(false);
          expect(them.feeds.length).toBe(other.partyManager.identityManager.deviceManager.devices.length);
          expect(them.displayName).toEqual(other.partyManager.identityManager.displayName);
        }
      }
    });
  }
};

/**
 * Makes sure the Contact details match what is expected across all nodes.
 */
export const checkContacts = async (nodes) => {
  for await (const node of nodes) {
    await waitForExpect(async () => {
      const contacts = await node.partyManager.getContacts();
      const expectedContacts = nodes.length - 1;
      if (contacts.length > expectedContacts) {
        console.warn(contacts);
      }
      expect(contacts.length).toEqual(expectedContacts);
      for (const other of nodes) {
        if (other !== node) {
          const match = contacts.find(contact => contact.publicKey.equals(other.partyManager.identityManager.publicKey));
          expect(match).toBeTruthy();
          expect(match.displayName).toEqual(other.partyManager.identityManager.displayName);
        }
      }
    });
  }
};

/**
 * Performs cleanup.
 * @param {TestNetworkNode[]} nodes
 */
export const destroyNodes = async (nodes) => {
  return Promise.all(nodes.map(node => node.destroy()));
};

/* eslint-disable no-await-in-loop */
/**
 * Create a new node and join it to the Party.
 * @param party
 * @param nodes
 * @returns {Promise<void>}
 */
export const addNodeToParty = async (party, nodes) => {
  const keyring = new Keyring();
  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  const node = new TestNetworkNode(keyring);
  await node.initialize({
    identityDisplayName: `Identity-${nodes.length}`,
    deviceDisplayName: `Identity-${nodes.length}-Device-0`
  });

  // Shared secret (out of band).
  const secret = '0000';

  // In real life, this would be generated and supplied to the inviter, so they could
  // communicate it to the invitee out-of-band (eg, voice, text, etc.).
  const greeterSecretProvider = async () => Buffer.from(secret);
  const greeterSecretValidator = async (invitation, secret) => secret && secret.equals(invitation.secret);

  // In real life, this one would wait for the user's input.
  const inviteeSecretProvider = async () => Buffer.from(secret);

  const invitation = await nodes[nodes.length - 1].partyManager.inviteToParty(party.publicKey,
    new InviteDetails(InviteType.INTERACTIVE, {
      secretProvider: greeterSecretProvider,
      secretValidator: greeterSecretValidator
    }));

  // And then redeem it on nodeB.
  await node.partyManager.joinParty(invitation, inviteeSecretProvider);
  nodes.push(node);
};

/**
 * Create a Party with the indicated number of members joined.
 * @param [memberCount=2]
 * @returns {Promise<{nodes: [], party: *}>}
 */
export const createTestParty = async (memberCount = 2) => {
  const nodes = [];

  const keyring = new Keyring();
  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  const node = new TestNetworkNode(keyring);
  await node.initialize({ identityDisplayName: 'Identity-0', deviceDisplayName: 'Identity-0-Device-0' });
  nodes.push(node);

  // Create the Party.
  const party = await nodes[0].partyManager.createParty();

  while (nodes.length < memberCount) {
    await addNodeToParty(party, nodes);
  }

  return { party, nodes };
};
/* eslint-enable no-await-in-loop */
