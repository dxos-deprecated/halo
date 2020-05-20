//
// Copyright 2019 DxOS
//

import debug from 'debug';

import { waitForEvent } from '@dxos/async';

import { checkPartyInfo, checkReplication, destroyNodes, createTestParty, addNodeToParty } from './testing/test-common';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:party-manager:test');

test('Check the PartyInfo of a party with 3 identities', async () => {
  const { party, nodes } = await createTestParty(3);
  await checkReplication(party.publicKey, nodes);
  await checkPartyInfo(party.publicKey, nodes);

  const [nodeA, nodeB, nodeC] = nodes;

  {
    const partyInfo = nodeA.partyManager.getPartyInfo(party.publicKey);
    expect(partyInfo.members.length).toBe(3);

    const memberA = partyInfo.members.find(member =>
      member.publicKey.equals(nodeA.partyManager.identityManager.publicKey));
    const memberB = partyInfo.members.find(member =>
      member.publicKey.equals(nodeB.partyManager.identityManager.publicKey));
    const memberC = partyInfo.members.find(member =>
      member.publicKey.equals(nodeC.partyManager.identityManager.publicKey));

    expect(memberA.isMe).toBe(true);
    expect(memberB.isMe).toBe(false);
    expect(memberC.isMe).toBe(false);

    expect(memberA.displayName).toEqual('Identity-0');
    expect(memberB.displayName).toEqual('Identity-1');
    expect(memberC.displayName).toEqual('Identity-2');

    expect(memberA.admittedBy).toEqual(party.publicKey);
    expect(memberB.admittedBy).toEqual(memberA.publicKey);
    expect(memberC.admittedBy).toEqual(memberB.publicKey);

    // Check that adding a new member to the party fires an 'update'.
    const waiter = waitForEvent(partyInfo, 'update',
      (member) => member.displayName === 'Identity-3', 2000);

    await addNodeToParty(party, nodes);
    await waiter;

    expect(partyInfo.members.length).toBe(4);
  }

  await destroyNodes(nodes);
});
