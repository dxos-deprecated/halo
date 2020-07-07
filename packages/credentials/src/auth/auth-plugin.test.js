//
// Copyright 2019 DXOS.org
//

// dxos-testing-browser

import debug from 'debug';
import eos from 'end-of-stream';
import pify from 'pify';
import pump from 'pump';
import ram from 'random-access-memory';
import waitForExpect from 'wait-for-expect';

import { FeedStore } from '@dxos/feed-store';
import { Protocol } from '@dxos/protocol';
import { Replicator } from '@dxos/protocol-plugin-replicator';
import { keyToString, randomBytes } from '@dxos/crypto';

import { codec } from '../proto';
import { Authenticator } from './authenticator';
import { AuthPlugin } from './auth-plugin';
import { Keyring, KeyType } from '../keys';

const log = debug('dxos:creds:auth:test');

const createTestKeyring = async () => {
  const keyring = new Keyring();
  await keyring.load();

  for (const type of Object.keys(KeyType)) {
    await keyring.createKeyRecord({ type: KeyType[type] });
  }

  return keyring;
};

/**
 * A test Authenticator that checks for the signature of a pre-determined key.
 */
class ExpectedKeyAuthenticator extends Authenticator {
  constructor (keyring, expectedKey) {
    super();
    this._keyring = keyring;
    this._expectedKey = expectedKey;
  }

  async authenticate (credentials) {
    if (this._keyring.verify(credentials)) {
      if (this._expectedKey.equals(credentials.signatures[0].key)) {
        return true;
      }
    }

    return false;
  }
}

/**
 * Create and configure a Protocol object with all the necessary plugins for Auth and Replication.
 * There are a lot of steps to this. We need an Auth plugin, the credentials, and and an Authenticator to check them,
 * we need a Replicator and a Feed to replicate, and we need a Protocol to attach the plugins too.
 * Basically, we need all of data-client but in one fairly small function.
 * @param partyKey
 * @param authenticator
 * @param keyring
 * @returns {{auth: AuthPlugin, proto: Protocol, id: *}}
 * @listens AuthPlugin#authenticated
 */
const createProtocol = async (partyKey, authenticator, keyring) => {
  const topic = keyToString(partyKey);
  const peerId = randomBytes(6); // createId();
  const feedStore = await FeedStore.create(ram, { feedOptions: { valueEncoding: 'utf8' } });
  const feed = await feedStore.openFeed(`/topic/${topic}/writable`, { metadata: { topic } });
  const append = pify(feed.append.bind(feed));

  // TODO(dboreham): abstract or remove outer wrapping.
  const credentials = codec.encode({
    __type_url: 'dxos.credentials.Message',
    payload: keyring.sign({
      __type_url: 'dxos.credentials.auth.Auth',
      partyKey,
      deviceKey: peerId,
      identityKey: peerId
    }, [keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE }))])
  }).toString('base64');

  const auth = new AuthPlugin(peerId, authenticator, [Replicator.extension]);
  const authPromise = new Promise((resolve) => {
    auth.on('authenticated', (incomingPeerId) => {
      log(`Authenticated ${keyToString(incomingPeerId)} on ${keyToString(peerId)}`);
      resolve();
    });
  });

  const openFeed = async (key) => {
    return feedStore.getOpenFeed(desc => desc.feed.key.equals(key)) ||
      feedStore.openFeed(`/topic/${topic}/readable/${keyToString(key)}`, { key, metadata: { topic } });
  };

  // Share and replicate all known feeds.
  const repl = new Replicator({
    load: async () => {
      return feedStore.getOpenFeeds();
    },

    subscribe: (add) => {
      const onFeed = feed => add(feed);
      feedStore.on('feed', onFeed);
      return () => {
        feedStore.removeListener('feed', onFeed);
      };
    },

    replicate: async (feeds) => {
      for await (const feed of feeds) {
        if (feed.key) {
          await openFeed(feed.key);
        }
      }

      return feedStore.getOpenFeeds();
    }
  });

  const getMessages = async () => {
    const messages = [];
    const stream = feedStore.createReadStream();
    stream.on('data', ({ data }) => {
      messages.push(data);
    });

    return new Promise((resolve, reject) => {
      eos(stream, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(messages.sort());
        }
      });
    });
  };

  const proto = new Protocol({
    streamOptions: { live: true }
  })
    .setSession({ peerId, credentials })
    .setExtension(auth.createExtension())
    .setExtension(repl.createExtension())
    .init(partyKey);

  return { id: peerId, auth, authPromise, proto, repl, feed, feedStore, append, getMessages };
};

/**
 * Pipe two Protocol objects together.
 * @param source
 * @param target
 */
const connect = (source, target) => {
  return pump(source.stream, target.stream, source.stream);
};

test('Auth Plugin (GOOD)', async () => {
  const keyring = await createTestKeyring();
  const partyKey = randomBytes(32);
  const node1 = await createProtocol(partyKey,
    new ExpectedKeyAuthenticator(keyring,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey), keyring);
  const node2 = await createProtocol(partyKey,
    new ExpectedKeyAuthenticator(keyring,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey), keyring);

  const connection = connect(node1.proto, node2.proto);
  await node1.authPromise;
  await node2.authPromise;

  connection.destroy();
});

test('Auth & Repl (GOOD)', async () => {
  const keyring = await createTestKeyring();
  const partyKey = randomBytes(32);
  const node1 = await createProtocol(partyKey,
    new ExpectedKeyAuthenticator(keyring,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey), keyring);
  const node2 = await createProtocol(partyKey,
    new ExpectedKeyAuthenticator(keyring,
      keyring.findKey(Keyring.signingFilter({ type: KeyType.DEVICE })).publicKey), keyring);

  const connection = connect(node1.proto, node2.proto);
  await node1.authPromise;
  await node2.authPromise;

  const message1 = randomBytes(32).toString('hex');
  await node1.append(message1);
  await waitForExpect(async () => {
    const msgs = await node2.getMessages();
    expect(msgs).toContain(message1);
    log(`${message1} on ${keyToString(node2.id)}.`);
  });

  const message2 = randomBytes(32).toString('hex');
  await node2.append(message2);
  await waitForExpect(async () => {
    const msgs = await node1.getMessages();
    expect(msgs).toContain(message2);
    log(`${message2} on ${keyToString(node1.id)}.`);
  });

  connection.destroy();
});
