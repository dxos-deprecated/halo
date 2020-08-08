//
// Copyright 2019 DXOS.org
//

// dxos-testing-browser

import assert from 'assert';

import { expectToThrow } from '@dxos/async';
import { createKeyPair, keyToString, randomBytes } from '@dxos/crypto';

import { Filter } from './filter';
import { Keyring } from './keyring';
import { KeyType } from './keytype';

test('Generate keys', async () => {
  const keyring = new Keyring();

  const byType = new Map();
  for await (const type of Object.keys(KeyType)) {
    const keyRecord = await keyring.createKeyRecord({ type: KeyType[type] });
    byType.set(type, keyRecord);
  }

  for (const type of Object.keys(KeyType)) {
    const match = keyring.findKey(Filter.matches({ type: KeyType[type] }));
    expect(match.publicKey).toEqual(byType.get(type).publicKey);
    expect(keyring.hasSecretKey(match)).toBe(true);
  }
});

test('Update a key', async () => {
  const keyring = new Keyring();
  const record = await keyring.createKeyRecord({ type: KeyType.DEVICE });

  {
    const stored = keyring.getKey(record.publicKey);
    expect(keyring.hasSecretKey(stored)).toBe(true);
    expect(stored.trusted).toBe(true);
  }

  const { ...copy } = record;
  copy.trusted = false;

  await keyring.updateKey(copy);

  {
    const stored = keyring.getKey(record.publicKey);
    expect(keyring.hasSecretKey(stored)).toBe(true);
    expect(stored.trusted).toBe(false);
  }
});

test('Bad key attributes', async (done) => {
  const keyring = new Keyring();
  try {
    await keyring.createKeyRecord({ id: 'xxx' });
    done.fail('Allowed invalid attributes.');
  } catch (err) {
    expect(err).toBeTruthy();
  }
  done();
});

test('Add/retrieve single keyRecord from an external source', async () => {
  const external = createKeyPair();
  const keyring = new Keyring();
  await keyring.addKeyRecord(external);

  const internal = keyring.getKey(external.publicKey);
  expect(keyToString(internal.publicKey)).toEqual(keyToString(external.publicKey));
  expect(keyring.hasSecretKey(internal)).toBe(true);
});

test('Try to add/retrieve a publicKey from an external source (with secret present)', async (done) => {
  const external = createKeyPair();
  const keyring = new Keyring();

  try {
    await keyring.addPublicKey(external);
    done.fail('Allowed addPublicKey with secretKey present.');
  } catch (err) {
    expect(err).toBeTruthy();
  }

  done();
});

test('Add/retrieve a publicKey from an external source (without secret present)', async () => {
  const external = { publicKey: createKeyPair().publicKey };
  const keyring = new Keyring();
  await keyring.addPublicKey(external);

  const stored = keyring.getKey(external.publicKey);
  expect(stored.publicKey).toEqual(external.publicKey);
  expect(keyring.hasSecretKey(stored)).toBe(false);
});

test('Retrieve a non-existent key', async () => {
  const keyring = new Keyring();
  const internal = keyring.findKey(Filter.matches({ key: keyToString(randomBytes(32)) }));
  expect(internal).toBeUndefined();
});

test('Sign and verify a message with a single key', async () => {
  const keyring = new Keyring();
  const original = await keyring.createKeyRecord({ type: KeyType.IDENTITY });

  const signed = keyring.sign({ message: 'Test' }, [
    keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY }))
  ]);
  expect(signed.signatures.length).toBe(1);
  expect(signed.signatures[0].key).toEqual(original.publicKey);

  const verified = keyring.verify(signed);
  expect(verified).toBe(true);
});

test('Sign and verify a message with multiple keys', async () => {
  const keyring = new Keyring();
  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const keys = [
    keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
    keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))
  ];

  const signed = keyring.sign({ message: 'Test' }, keys);
  expect(signed.signatures.length).toEqual(keys.length);

  const strKeys = keys.map(key => keyToString(key.publicKey));
  for (const sig of signed.signatures) {
    expect(strKeys).toContain(keyToString(sig.key));
  }

  const verified = keyring.verify(signed);
  expect(verified).toBe(true);
});

test('Sign and verify a message using a key chain', async () => {
  const keyringA = new Keyring();
  const identityA = await keyringA.createKeyRecord({ type: KeyType.IDENTITY });
  const deviceAA = await keyringA.createKeyRecord({ type: KeyType.DEVICE });
  const deviceAB = await keyringA.createKeyRecord({ type: KeyType.DEVICE });

  // Trust IdentityA, but not DeviceA.
  const keyringB = new Keyring();
  await keyringB.addPublicKey(identityA);

  const keyMessages = new Map();
  keyMessages.set(identityA.key, keyringA.sign({ message: 'Test' }, [identityA]));
  keyMessages.set(deviceAA.key, keyringA.sign({ message: 'Test' }, [identityA, deviceAA]));
  keyMessages.set(deviceAB.key, keyringA.sign({ message: 'Test' }, [deviceAB, deviceAA]));

  const deviceABChain = Keyring.buildKeyChain(deviceAB.publicKey, keyMessages);

  const signed = keyringA.sign({ message: 'Test' }, [deviceABChain]);
  expect(signed.signatures.length).toBe(1);
  expect(signed.signatures[0].key).toEqual(deviceAB.publicKey);
  expect(signed.signatures[0].keyChain).toBeTruthy();

  {
    const verified = keyringA.verify(signed);
    expect(verified).toBe(true);
  }
  {
    const verified = keyringB.verify(signed);
    expect(verified).toBe(true);
  }
  {
    const verified = keyringB.verify(signed, { allowKeyChains: false });
    expect(verified).toBe(false);
  }
});

test('Attempt to sign a message with a publicKey', async () => {
  const keyring = new Keyring();
  const original = await keyring.createKeyRecord({ type: KeyType.PARTY });

  // This should work.
  {
    const stored = keyring.getKey(original.publicKey);
    const signed = keyring.sign({ message: 'Test' }, [stored]);
    expect(signed.signatures.length).toBe(1);
    expect(keyring.verify(signed)).toBe(true);
  }

  // Erase the secretKey.
  {
    await keyring.deleteSecretKey(original);
    const stored = keyring.getKey(original.publicKey);
    expect(stored).toBeTruthy();
    expect(keyring.hasSecretKey(stored)).toBe(false);
    expect(() => {
      keyring.sign({ message: 'Test' }, [stored]);
    }).toThrow(assert.AssertionError);
  }
});

test('Attempt to add a badly formatted key', async () => {
  const keyring = new Keyring();
  const good = createKeyPair();
  const bad = {
    publicKey: keyToString(good.publicKey),
    secretKey: keyToString(good.secretKey)
  };

  await expectToThrow(() => keyring.addKeyRecord(bad), assert.AssertionError);
});

test('Attempt to add a keyRecord missing its secretKey', async () => {
  const keyring = new Keyring();
  const good = createKeyPair();
  const bad = {
    publicKey: good.publicKey
  };

  await expectToThrow(() => keyring.addKeyRecord(bad), assert.AssertionError);
});

test('Attempt to add a keyRecord missing its publicKey', async () => {
  const keyring = new Keyring();
  const good = createKeyPair();
  const bad = {
    secretKey: good.secretKey
  };

  await expectToThrow(() => keyring.addKeyRecord(bad), assert.AssertionError);
});

test('Attempt to add keyRecord with reversed publicKey/secretKey', async () => {
  const keyring = new Keyring();
  const good = createKeyPair();
  const bad = {
    secretKey: good.publicKey,
    publicKey: good.secretKey
  };

  await expectToThrow(() => keyring.addKeyRecord(bad), assert.AssertionError);
});

test('Attempt to add secretKey as a publicKey', async () => {
  const { secretKey } = createKeyPair();
  const keyring = new Keyring();
  const bad = {
    publicKey: secretKey
  };

  await expectToThrow(() => keyring.addPublicKey(bad), assert.AssertionError);
});

test('Tamper with the contents of a signed message', async () => {
  const keyring = new Keyring();
  const message = { a: 'A', b: 'B', c: 'C' };

  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const signedCopy = keyring.sign(message, [
    keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
    keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))
  ]);

  expect(keyring.verify(signedCopy)).toBe(true);

  signedCopy.signed.C = 'D';
  expect(keyring.verify(signedCopy)).toBe(false);
});

test('Tamper with the signature of a signed message', async () => {
  const keyring = new Keyring();
  const message = { a: 'A', b: 'B', c: 'C' };

  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const signedCopy = keyring.sign(message, [
    keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
    keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))
  ]);

  expect(keyring.verify(signedCopy)).toBe(true);

  signedCopy.signatures[1].signature = randomBytes(64);
  expect(keyring.verify(signedCopy)).toBe(false);
});

test('Tamper with the signature key of a signed message', async () => {
  const keyring = new Keyring();
  await keyring.createKeyRecord({ type: KeyType.IDENTITY });
  await keyring.createKeyRecord({ type: KeyType.DEVICE });

  const message = { a: 'A', b: 'B', c: 'C' };
  const signedCopy = keyring.sign(message, [
    keyring.findKey(Keyring.signingFilter({ type: KeyType.IDENTITY })),
    keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))
  ]);
  expect(keyring.verify(signedCopy)).toBe(true);

  signedCopy.signatures[1].key = randomBytes(32);
  expect(keyring.verify(signedCopy)).toBe(false);
});

test('To/from JSON', async () => {
  const original = new Keyring();
  for (const type of Object.keys(KeyType)) {
    await original.createKeyRecord({ type: KeyType[type] });
  }

  const copy = new Keyring();
  await copy.loadJSON(original.toJSON());

  expect(original.toJSON()).toEqual(copy.toJSON());
  expect(copy.keys).toEqual(original.keys);
});
