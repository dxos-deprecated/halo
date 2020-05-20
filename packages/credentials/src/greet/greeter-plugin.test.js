//
// Copyright 2019 DxOS
//

import debug from 'debug';
import pump from 'pump';

import { keyToString, keyToBuffer, randomBytes } from '@dxos/crypto';
import { Protocol } from '@dxos/protocol';

import { Greeter, Command } from './greeter';
import { GreeterPlugin } from './greeter-plugin';
import { Keyring, KeyType } from '../keys';
import { createKeyAdmitMessage } from '../party';

const log = debug('dxos:creds:greet');

/**
 * Create the Greeter with Plugin and Protocol.
 * @param targetPartyKey
 */
const createGreeter = async (targetPartyKey) => {
  let outerResolve;
  const writePromise = new Promise((resolve) => {
    outerResolve = resolve;
  });

  const hints = [
    { publicKey: randomBytes(32), type: KeyType.IDENTITY },
    { publicKey: randomBytes(32), type: KeyType.DEVICE },
    { publicKey: randomBytes(32), type: KeyType.FEED },
    { publicKey: randomBytes(32), type: KeyType.FEED }
  ];

  const greeter = new Greeter(
    targetPartyKey,
    messages => outerResolve(messages),
    () => hints
  );

  const peerId = randomBytes(32);
  const plugin = new GreeterPlugin(peerId, greeter.createMessageHandler());

  const protocol = new Protocol({
    streamOptions: {
      live: true
    }
  })
    .setSession({ peerId })
    .setExtension(plugin.createExtension())
    .init(peerId);

  return { greeter, rendezvousKey: peerId, plugin, protocol, writePromise, hints };
};

/**
 * Create the Invitee with Plugin and Protocol.
 * @param {Buffer} rendezvousKey
 * @param {string} invitationId
 */
export const createInvitee = async (rendezvousKey, invitationId) => {
  const peerId = keyToBuffer(invitationId);

  const invitee = new Greeter();
  const plugin = new GreeterPlugin(peerId, invitee.createMessageHandler());

  const connectionPromise = new Promise(resolve => {
    plugin.on('peer:joined', (peerId) => {
      if (peerId && keyToString(peerId) === keyToString(rendezvousKey)) {
        log(`${keyToString(peerId)} connected.`);
        resolve();
      }
    });
  });

  const protocol = new Protocol({
    streamOptions: {
      live: true
    }
  })
    .setSession({ peerId })
    .setExtension(plugin.createExtension())
    .init(rendezvousKey);

  // TODO(burdon): Bad return object (too many things).
  return { protocol, invitee, plugin, peerId, connectionPromise };
};

/**
 * Connect two Protocols together.
 * @param {Protocol} source
 * @param {Protocol} target
 */
const connect = (source, target) => {
  return pump(source.stream, target.stream, source.stream);
};

test('Greeting Flow using GreeterPlugin', async () => {
  const targetPartyKey = randomBytes(32);
  const secret = '0000';

  const secretProvider = async () => Buffer.from(secret);
  const secretValidator = async (invitation, secret) => secret && secret.equals(invitation.secret);

  const {
    protocol: greeterProtocol, greeter, rendezvousKey, hints, writePromise
  } = await createGreeter(targetPartyKey);

  const invitation = await greeter.createInvitation(targetPartyKey, secretValidator, secretProvider);

  const {
    protocol: inviteeProtocol, plugin, connectionPromise
  } = await createInvitee(rendezvousKey, invitation.id);

  connect(greeterProtocol, inviteeProtocol);

  await connectionPromise;

  // Present the invitation (by showing up).
  {
    const command = {
      __type_url: 'dxos.credentials.greet.Command',
      command: Command.Type.PRESENT
    };

    await plugin.send(rendezvousKey, command);
  }

  // Obtain the nonce and partyKey from the NEGOTIATE response.
  const { nonce, partyKey } = await (async () => {
    const command = {
      __type_url: 'dxos.credentials.greet.Command',
      command: Command.Type.NEGOTIATE,
      secret: await secretProvider(),
      params: []
    };

    const { nonce, partyKey } = await plugin.send(rendezvousKey, command);
    return { nonce, partyKey };
  })();

  // Create a signed credential and submit it to the Greeter for "writing" (see writePromise).
  {
    const keyring = new Keyring();
    const identityKey = await keyring.createKeyRecord({ type: KeyType.IDENTITY });

    const command = {
      __type_url: 'dxos.credentials.greet.Command',
      command: Command.Type.SUBMIT,
      secret: await secretProvider(),
      params: [
        createKeyAdmitMessage(keyring,
          partyKey,
          identityKey,
          identityKey,
          nonce)
      ]
    };

    // Send them to the greeter.
    const submitResponse = await plugin.send(rendezvousKey, command);
    expect(submitResponse.hints).toEqual(hints);

    // In the real world, the response would be signed in an envelope by the Greeter, but in this test it is not altered.
    expect(await writePromise).toEqual(command.params);
  }

  await plugin.send(rendezvousKey, {
    __type_url: 'dxos.credentials.greet.Command',
    command: Command.Type.FINISH,
    secret: await secretProvider()
  });
});
