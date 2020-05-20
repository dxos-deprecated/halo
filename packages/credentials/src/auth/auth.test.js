//
// Copyright 2019 DxOS
//

// dxos-testing-browser

import debug from 'debug';
import moment from 'moment';

import { randomBytes, keyToString } from '@dxos/crypto';

import {
  admitsKeys,
  createEnvelopeMessage,
  createKeyAdmitMessage,
  createPartyGenesisMessage,
  Party
} from '../party';
import { validate } from '../proto';
import { Filter, Keyring, KeyType } from '../keys';

import { PartyAuthenticator } from './authenticator';
import { createAuthMessage } from './auth-message';

// eslint-disable-next-line no-unused-vars
const log = debug('dxos:creds:auth:test');

const createPartyKeyrings = async () => {
  // This Keyring has the full key pairs, which is the case when creating a new Party.
  const keyring = new Keyring();
  for (const type of Object.keys(KeyType)) {
    await keyring.createKeyRecord({ type: KeyType[type] });
  }

  const partyKey = keyring.findKey(Filter.matches({ type: KeyType.PARTY })).publicKey;

  // This Keyring will have nothing but the public key of the Party. This mimics the initial state
  // when joining a Party, since all that is known at that time know at that time is the public key.
  const bareKeyring = new Keyring();
  await bareKeyring.addPublicKey({
    publicKey: partyKey,
    type: KeyType.PARTY,
    trusted: true,
    own: false
  });

  return {
    partyKey,
    keyring,
    bareKeyring
  };
};

// eslint-disable-next-line no-unused-vars
const chainToString = (chain, depth = 0) => {
  let ret = keyToString(chain.publicKey) + '\n';
  if (chain.parents.length) {
    depth += 1;
    for (const parent of chain.parents) {
      let spaces = '';
      for (let i = 0; i < depth; i++) {
        spaces += '  ';
      }
      ret += `${spaces}-> ${chainToString(parent, depth)}`;
    }
  }
  return ret;
};

const messageMap = (messages) => {
  const map = new Map();
  for (const message of messages) {
    const admits = admitsKeys(message);
    for (const key of admits) {
      map.set(keyToString(key), message);
    }
  }
  return map;
};

const getIdentityKeyChainForDevice = (keyring, devicePublicKey, messages) => {
  // Excludes all the FEED keys.
  return Keyring.buildKeyChain(devicePublicKey, messages,
    keyring.findKeys(Filter.matches({ type: KeyType.FEED })).map(key => key.publicKey));
};

test('Chain of Keys', async () => {
  const hubKeyring = new Keyring();
  const identityKey = await hubKeyring.createKeyRecord({ type: KeyType.PARTY });
  const deviceKeyA = await hubKeyring.createKeyRecord({ type: KeyType.DEVICE });
  const deviceKeyB = await hubKeyring.createKeyRecord({ type: KeyType.DEVICE });
  const deviceKeyC = await hubKeyring.createKeyRecord({ type: KeyType.DEVICE });
  const feedKeyA = await hubKeyring.createKeyRecord({ type: KeyType.FEED });

  const messages = new Map();

  // The first message in the chain in always a PartyGenesis for the IdentityHub.
  messages.set(keyToString(identityKey.publicKey), createPartyGenesisMessage(hubKeyring, identityKey, feedKeyA, deviceKeyA));
  messages.set(keyToString(deviceKeyA.publicKey), messages.get(keyToString(identityKey.publicKey)));
  messages.set(keyToString(feedKeyA.publicKey), messages.get(keyToString(identityKey.publicKey)));

  // Next is DeviceB greeted by DeviceA.
  messages.set(keyToString(deviceKeyB.publicKey),
    createEnvelopeMessage(hubKeyring, identityKey.publicKey,
      createKeyAdmitMessage(hubKeyring, identityKey.publicKey, deviceKeyB, [deviceKeyB]),
      [deviceKeyA]
    ));

  // Next is DeviceC greeted by DeviceB.
  messages.set(keyToString(deviceKeyC.publicKey),
    createEnvelopeMessage(hubKeyring, identityKey.publicKey,
      createKeyAdmitMessage(hubKeyring, identityKey.publicKey, deviceKeyC, [deviceKeyC]),
      [deviceKeyB]
    ));

  const targetKeyring = new Keyring();
  await targetKeyring.addPublicKey({
    publicKey: identityKey.publicKey,
    type: KeyType.IDENTITY,
    trusted: true,
    own: false
  });

  for (const deviceKey of [deviceKeyA, deviceKeyB, deviceKeyC]) {
    const emptyKeyring = new Keyring();
    const chain = Keyring.buildKeyChain(deviceKey.publicKey, messages);
    // In the target keyring, which only has the Identity, it should chase all the way back to the Identity.
    expect(identityKey.publicKey).toEqual((await targetKeyring.findTrusted(chain)).publicKey);
    // And in the hub, which has all the keys, it should chase straight back to this key.
    expect(deviceKey.publicKey).toEqual((await hubKeyring.findTrusted(chain)).publicKey);
    // And in an empty Keyring, we should not get anything.
    expect(await emptyKeyring.findTrusted(chain)).toBeUndefined();
  }
});

test('PartyAuthenticator - good direct', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);

  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  // Only add the Identity to the party keyring.
  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      identityKeyRecord,
      identityKeyRecord
    )
  );

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(true);
});

test('PartyAuthenticator - good chain', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);

  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));
  const deviceKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));
  const secondDeviceKeyRecord = await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  // Only add the Identity to the party keyring.
  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      identityKeyRecord,
      getIdentityKeyChainForDevice(
        keyring,
        secondDeviceKeyRecord.publicKey,
        messageMap([
          ...messages,
          createKeyAdmitMessage(keyring, partyKey, deviceKeyRecord, [identityKeyRecord]),
          createKeyAdmitMessage(keyring, partyKey, secondDeviceKeyRecord, [deviceKeyRecord])
        ]
        )
      )
    )
  );

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(true);
});

test('PartyAuthenticator - bad chain', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);

  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));
  const deviceKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));
  const secondDeviceKeyRecord = await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  // Only add the Identity to the party keyring.
  await party.processMessages(messages);

  // A bad chain, it doesn't track back to the Identity.
  const chain = getIdentityKeyChainForDevice(
    keyring,
    secondDeviceKeyRecord.publicKey,
    messageMap([
      ...messages,
      createKeyAdmitMessage(keyring, partyKey, deviceKeyRecord, [deviceKeyRecord]),
      createKeyAdmitMessage(keyring, partyKey, secondDeviceKeyRecord, [deviceKeyRecord])
    ]
    )
  );

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      identityKeyRecord,
      secondDeviceKeyRecord,
      chain
    )
  );

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

// TODO(dboreham): This test isn't discriminating errors because when I broke the code entirely it still passed.
test('PartyAuthenticator - wrong key', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const wrongKey = await keyring.createKeyRecord();

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ];
  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
      wrongKey
    )
  );

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

test('PartyAuthenticator - wrong party', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];
  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      randomBytes(32),
      identityKeyRecord,
      identityKeyRecord
    )
  );

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

test('PartyAuthenticator - missing deviceKey', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);

  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
    )
  ];
  await party.processMessages(messages);

  const wrappedCredentials = {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.auth.Auth',
        partyKey,
        identityKey: identityKeyRecord.publicKey
      }, [identityKeyRecord])
  };

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

test('PartyAuthenticator - tampered message', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      identityKeyRecord,
      identityKeyRecord
    )
  );

  const before = await auth.authenticate(wrappedCredentials.payload);
  expect(before).toBe(true);

  wrappedCredentials.payload.signed.payload.deviceKey = randomBytes(32);

  const after = await auth.authenticate(wrappedCredentials.payload);
  expect(after).toBe(false);
});

test('PartyAuthenticator - tampered signature', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  await party.processMessages(messages);

  const wrappedCredentials = validate(
    createAuthMessage(
      keyring,
      partyKey,
      identityKeyRecord,
      identityKeyRecord
    )
  );

  const before = await auth.authenticate(wrappedCredentials.payload);
  expect(before).toBe(true);

  wrappedCredentials.payload.signatures[0].signature = randomBytes(64);

  const after = await auth.authenticate(wrappedCredentials.payload);
  expect(after).toBe(false);
});

test('PartyAuthenticator - signature too old', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));
  const deviceKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  await party.processMessages(messages);

  const wrappedCredentials = {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.auth.Auth',
        partyKey,
        identityKey: identityKeyRecord.publicKey,
        deviceKey: deviceKeyRecord.publicKey
      },
      [identityKeyRecord],
      null,
      moment().subtract(2, 'days').format('YYYY-MM-DDTHH:mm:ssZ')
      )
  };

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

test('PartyAuthenticator - signature too far in future', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));
  const deviceKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  await party.processMessages(messages);

  const wrappedCredentials = {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.auth.Auth',
        partyKey,
        identityKey: identityKeyRecord.publicKey,
        deviceKey: deviceKeyRecord.publicKey
      },
      [identityKeyRecord],
      null,
      moment().add(2, 'days').format('YYYY-MM-DDTHH:mm:ssZ')
      )
  };

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});

test('PartyAuthenticator - signature date invalid', async () => {
  const { keyring, partyKey } = await createPartyKeyrings();
  const party = new Party(partyKey, keyring);
  const auth = new PartyAuthenticator(party);
  const identityKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }));
  const deviceKeyRecord = keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }));

  const messages = [
    createPartyGenesisMessage(keyring,
      keyring.findKey(Filter.matches({ type: KeyType.PARTY })),
      keyring.findKey(Keyring.signingFilter({ type: KeyType.FEED })),
      identityKeyRecord
    )
  ];

  await party.processMessages(messages);

  const wrappedCredentials = {
    __type_url: 'dxos.credentials.Message',
    payload:
      keyring.sign({
        __type_url: 'dxos.credentials.auth.Auth',
        partyKey,
        identityKey: identityKeyRecord.publicKey,
        deviceKey: deviceKeyRecord.publicKey
      },
      [identityKeyRecord],
      null,
      'INVALID'
      )
  };

  const ok = await auth.authenticate(wrappedCredentials.payload);
  expect(ok).toBe(false);
});
