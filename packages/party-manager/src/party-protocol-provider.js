//
// Copyright 2020 DXOS.org
//

// TODO(dboreham): Clean up and document this old code.
// TODO(burdon): Check swarm related functionality. E.g., error handling, open/close, etc.

// Encapsulate the specialization of @dxos/protocol and @dxos/protocol-plugin-replicator functionality
//   for Party and Identity: Use Party replication feed selection logic and Party replication authentication.
//   Use Party Greeting authentication for Greeting connections. Used in conjunction with @dxos/network-manager.

import assert from 'assert';
import debug from 'debug';

import {
  AuthPlugin,
  PartyAuthenticator,
  GreetingCommandPlugin
} from '@dxos/credentials';
import { keyToString, discoveryKey, keyToBuffer } from '@dxos/crypto';
import { Protocol } from '@dxos/protocol';
import { Replicator } from '@dxos/protocol-plugin-replicator';
import { protocolFactory } from '@dxos/network-manager';

import { makePartyInvitationClaimHandler } from './party-invitation-claims';

const log = debug('dxos:party-manager:protocol-provider');

/**
 * Create middleware objects for Replicator.
 * @param {FeedStore} feedStore
 * @param {Party} party
 * @returns {Replicator}
 */
const partyReplicatorFactory = (feedStore, party) => {
  const openFeed = async (key) => {
    const topic = keyToString(party.publicKey);

    // Get the feed if we have it already, else create it.
    return feedStore.getOpenFeed(desc => desc.feed.key.equals(key)) ||
      feedStore.openFeed(`/topic/${topic}/readable/${keyToString(key)}`, { key, metadata: { topic } });
  };

  return new Replicator({
    load: async () => {
      // Tell the Replicator about all our existing Party feeds.  We have to tell it _something_, but we only tell it
      // the discoveryKey, not the real key, to prevent leaking information about the Party.
      const partyFeeds = await Promise.all(party.memberFeeds.map(feedKey => openFeed(feedKey)));
      return partyFeeds.map((feed) => {
        return { discoveryKey: feed.discoveryKey };
      });
    },

    subscribe: (addFeedToReplicatedSet) => {
      /** @listens Party#'admit:feed' */
      // When a new feed is admitted to the Party, open it and tell the Replicator about it (discoveryKey only).
      const onNewFeed = async (feedKey) => {
        const feed = await openFeed(feedKey.publicKey);
        addFeedToReplicatedSet({ discoveryKey: feed.discoveryKey });
      };

      party.on('admit:feed', onNewFeed);

      // Return a function to be called when the Peer disconnects.
      return () => party.off('admit:feed', onNewFeed);
    },

    replicate: async (/* remoteFeeds, info */) => {
      // We can ignore remoteFeeds entirely, because the set of feeds we want to replicate is dictated by the Party.
      // TODO(telackey): why are we opening feeds? Necessary or belt/braces thinking, or because open party does it?
      return Promise.all(party.memberFeeds.map(feedKey => openFeed(feedKey)));
    }
  });
};

/**
 * Create a protocol factory function with the supplied session, protocol plugins and getTopics() decorator function.
 * @param {Object} session
 * @param {ProtocolPlugin[]} plugins
 * @param getTopics
 * @param {Party} party
 * @return {function({channel?: *, protocolContext: *}): *}
 */
const replicatorProtocolFactory = ({ session = {}, plugins = [], getTopics, party }) => {
  assert(getTopics);
  assert(party);
  return ({ channel, protocolContext }) => {
    const { feedStore } = protocolContext;
    assert(feedStore);
    plugins.push(partyReplicatorFactory(feedStore, party));

    const protocol = new Protocol({
      streamOptions: { live: true },
      discoveryToPublicKey: (dk) => {
        const publicKey = getTopics().find(topic => discoveryKey(topic).equals(dk));
        if (publicKey) {
          protocol.setContext({ topic: keyToString(publicKey) });
        }
        return publicKey;
      }
    });

    protocol
      .setSession(session)
      .setExtensions(plugins.map(plugin => plugin.createExtension()))
      .init(channel);

    log('Created replication protocol.');
    return protocol;
  };
};

/**
 * Creates a p2p connection implementing Party replication logic and Party-based connection authentication.
 * @param {PublicKey} peerId
 * @param {} credentials
 * @param {Party} party
 * @param {PartyManager} partyManager
 * @return {function({channel?: *, protocolContext: *}): *}
 */
export const partyProtocolProvider = (peerId, credentials, party, partyManager) => {
  const partyInfo = partyManager.getPartyInfo(party.publicKey);
  return replicatorProtocolFactory({
    getTopics: () => {
      return [keyToBuffer(party.topic)];
    },

    session: {
      peerId,
      // TODO(telackey): This ought to be a callback so that fresh credentials can be minted when needed.
      credentials: PartyAuthenticator.encodePayload(credentials).toString('base64')
    },

    plugins: [
      new AuthPlugin(peerId, new PartyAuthenticator(party), [Replicator.extension]),
      // Only deals with written PartyInvitation messages, handing them over to the regular Greeting flow.
      new GreetingCommandPlugin(peerId, makePartyInvitationClaimHandler(party, partyManager)),
      // TODO(dboreham): add back removed ability for the client.js caller to specify additional plugins.
      // ...plugins
      ...(partyInfo ? [partyInfo.presence] : []) // make sure to not add undefined element to the array
    ],

    party
  });
};

/**
 * Creates a duplex connection with a single peer using a common rendezvous key as topic.
 * @param peerId
 * @param protocolPlugins
 * @param rendezvousKey
 * @return {Object} swarm
 */
// TODO(burdon): When closed?
// TODO(dboreham): Write a test to check resources are released (no resource leaks).
export const greetingProtocolProvider = (rendezvousKey, peerId, protocolPlugins) => {
  return protocolFactory({
    getTopics: () => {
      return [rendezvousKey];
    },
    session: { peerId },
    plugins: protocolPlugins
  });
};
