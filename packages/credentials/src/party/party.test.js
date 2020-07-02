//
// Copyright 2019 DxOS
//

// dxos-testing-browser

import debug from 'debug';

import { expectToThrow } from '@dxos/async';

import { Filter, Keyring, KeyType } from '../keys';
import { validate } from '../proto';

import { Party } from './party';
import {
  createEnvelopeMessage,
  createFeedAdmitMessage,
  createKeyAdmitMessage,
  createPartyGenesisMessage
} from './party-credential';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:creds:party:test');

const createPartyKeyrings = async () => {
  // This Keyring has all the keypairs, so it is the initial source of things.
  const keyring = new Keyring();
  for (const type of Object.keys(KeyType)) {
    await keyring.createKeyRecord({ type: KeyType[type] });
  }

  const partyKey = keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey;

  return {
    partyKey,
    keyring
  };
};

test('Process basic message types', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });

  const party = new Party(partyKey);

  const messages = [
    // The Genesis message is signed by the party private key, the feed key, and one admitted key.
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))),
    // A user (represented by the identity key) will also need a device.
    createKeyAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })),
      [keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))]),
    // We don't actually need this feed, since the initial feed is in the Genesis message, but we want to test all types.
    createFeedAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[1],
      [keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))])
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys).toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })).publicKey);
  expect(party.memberKeys).toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey);
  expect(party.memberFeeds).toContainEqual(keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0].publicKey);
  expect(party.memberFeeds).toContainEqual(keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[1].publicKey);
});

test('GreetingCommandPlugin envelopes', async () => {
  const { keyring: greeterKeyring, partyKey } = await createPartyKeyrings();
  const { keyring: inviteeKeyring } = await createPartyKeyrings();

  const party = new Party(partyKey);
  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  const genesis = validate(
    createPartyGenesisMessage(greeterKeyring,
      greeterKeyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      greeterKeyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      greeterKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  );

  await party.processMessages([genesis]);

  expect(party.memberKeys).toContainEqual(greeterKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })).publicKey);

  // A self-signed admit message wrapped in a greeter-signed envelope.
  const pseudo = createKeyAdmitMessage(inviteeKeyring,
    partyKey,
    inviteeKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
    [inviteeKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))]);

  const envelope = validate(
    createEnvelopeMessage(greeterKeyring,
      partyKey,
      pseudo,
      greeterKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  );

  await party.processMessages([envelope]);
  expect(party.memberKeys).toContainEqual(inviteeKeyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })).publicKey);
});

test('Reject message from unknown source', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey);
  const alienKey = await keyring.createKeyRecord();

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))),
    createKeyAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })),
      [alienKey])
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys).toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })).publicKey);
  expect(party.memberKeys).not.toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey);
  expect(party.memberKeys).not.toContainEqual(alienKey.publicKey);
});

test('Message signed by known and unknown key should not admit unknown key', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey);
  const alienKey = await keyring.createKeyRecord();

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))),
    createKeyAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })),
      [alienKey, keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))])
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys).toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })).publicKey);
  expect(party.memberKeys).toContainEqual(keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey);
  expect(party.memberKeys).not.toContainEqual(alienKey.publicKey);
});

test('Reject Genesis not signed by Party key', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey);
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const wrongKey = await keyring.createKeyRecord();

  const messages = [
    createPartyGenesisMessage(keyring,
      wrongKey,
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);
});

test('Reject admit key message with wrong Party', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const party = new Party(partyKey);
  const wrongParty = await keyring.createKeyRecord();

  let messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);

  messages = [
    createKeyAdmitMessage(keyring,
      wrongParty.publicKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);
});

test('Reject admit feed message with wrong Party', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const party = new Party(partyKey);
  const wrongParty = await keyring.createKeyRecord();

  let messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);

  messages = [
    createFeedAdmitMessage(keyring,
      wrongParty.publicKey,
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[1],
      [keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))]
    )
  ].map(validate);

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);
});

test('Reject tampered Genesis message', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const party = new Party(partyKey);

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  messages[0].payload.signed.nonce = Buffer.from('wrong');

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);
});

test('Reject tampered admit feed message', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const party = new Party(partyKey);

  let messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);

  messages = [
    createFeedAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[1],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ].map(validate);

  messages[0].payload.signed.nonce = Buffer.from('wrong');

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);
});

test('Reject tampered admit key message', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  await keyring.createKeyRecord({ type: KeyType.FEED });
  const party = new Party(partyKey);

  let messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKeys(Keyring.signingFilter({ type: KeyType.FEED }))[0],
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })))
  ].map(validate);

  expect(party.memberKeys.length).toEqual(0);
  expect(party.memberFeeds.length).toEqual(0);

  await party.processMessages(messages);

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);

  messages = [
    createKeyAdmitMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })),
      [keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))])
  ].map(validate);

  messages[0].payload.signed.nonce = Buffer.from('wrong');

  await expectToThrow(() => party.processMessages(messages));

  expect(party.memberKeys.length).toEqual(1);
  expect(party.memberFeeds.length).toEqual(1);
});
