//
// Copyright 2019 DXOS.org
//

// dxos-testing-browser

import memdown from 'memdown';

import { keyToString } from '@dxos/crypto';

import { Keyring } from './keyring';
import { createKeyRecord, stripSecrets } from './keyring-helpers';
import { KeyStore } from './keystore';
import { KeyType } from './keytype';

test('Basic store operations', async () => {
  const keystore = new KeyStore();
  const keyRecords = [];

  // Create and store some keys.
  for await (const type of Object.keys(KeyType)) {
    const keyRecord = createKeyRecord({ type: KeyType[type] });
    keyRecords.push(keyRecord);
    await keystore.setRecord(keyToString(keyRecord.publicKey), keyRecord);
  }

  // Do we have all the records?
  const values = await keystore.getRecords();
  expect(values.length).toBe(keyRecords.length);
  for (const keyRecord of keyRecords) {
    expect(values).toContainEqual(keyRecord);
  }

  // Can we get them by key?
  for await (const keyRecord of keyRecords) {
    expect(keyRecord).toEqual(await keystore.getRecord(keyToString(keyRecord.publicKey)));
  }

  // How about iterating the keys?
  const keys = await keystore.getKeys();
  expect(keys.length).toBe(keyRecords.length);
  for await (const key of keys) {
    expect(await keystore.getRecord(key)).toBeTruthy();
  }

  // How about key/value pairs?
  const entries = await keystore.getRecordsWithKey();
  expect(entries.length).toBe(keyRecords.length);
  for await (const entry of entries) {
    const [key, value] = entry;
    expect(key).toEqual(keyToString(value.publicKey));
  }
});

test('Test reloading', async () => {
  const db = memdown();
  const keyRecords = [];

  // Scope for initial seeding of the database.
  {
    const keystore = new KeyStore(db);
    const keyring = new Keyring(keystore);

    // Create and store some keys.
    for await (const type of Object.keys(KeyType)) {
      const keyRecord = await keyring.createKeyRecord({ type: KeyType[type] });
      keyRecords.push(keyring.getKey(keyRecord.publicKey));
    }

    // Do we have all the records?
    const values = await keystore.getRecords();
    expect(values.length).toBe(keyRecords.length);
    for await (const keyRecord of keyRecords) {
      expect(values.map(stripSecrets)).toContainEqual(keyRecord);
    }
  }

  // Scope for reloading from the database.
  {
    // Re-use the DB.
    const keystore = new KeyStore(db);
    const keyring = new Keyring(keystore);

    // Should be empty before loading from the KeyStore.
    expect(keyring.keys.length).toBe(0);

    // Load from the KeyStore.
    await keyring.load();

    // Do we have all the records now?
    const values = keyring.keys;
    expect(values.length).toBe(keyRecords.length);
    for await (const keyRecord of keyRecords) {
      expect(values.map(stripSecrets)).toContainEqual(keyRecord);
    }
  }
});
