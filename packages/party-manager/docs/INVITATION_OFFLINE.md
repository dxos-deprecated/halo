# Party Invitations using Public Keys
 
## Overview

The standard greeting process for new users is manual and interactive, requiring both the inviter and invitee
to be online at the same time and in communication with one another (eg, to exchange an authorization PIN).

However, for contacts whose public key is already known, it is possible to issue an invitation "offline",
which can be honored later by any Party member to authenticate and induct the invitee into the Party.

For example, Alice can invite Charlie, close her laptop, and go to lunch, and even while she is away, Charlie can
still accept the invitation and join the Party, so long as even one Party member (whether a bot, or the device
of a user) can be contacted.

## Issuing 

To issue an offline, key-based invitation use `InviteType.OFFLINE_KEY` as the type and specify the public key
of the entity that is being invited in the `InviteDetails`.

For example:

```javascript

const invitation = await partyManager.inviteToParty(partyKey,
  new InviteDetails(InviteType.OFFLINE_KEY, { publicKey: contactKey } ));

const link = createInvitationUrl(baseUrl, invitation.toQueryParameters());
console.log(link);

```

This will write a `PartyInvitation` message to the Party which, once replicated,
will allow any member of the Party (person or bot) to complete the invitation
process and admit the invitee.

## Redeeming

To redeem the invitation on the invitee, provide an `InvitationDescriptor` that represents the
invitation, as well as a `secretProvider` that returns an `Auth` message signed by the invited
key (or keychain).

```javascript

const invitation = InvitationDescriptor.fromQueryParameters(link.queryParameters);

// The secretProvider should provide an `Auth` message signed directly by the invited key,
// or by a keychain leading back to it. In this case, the invited key is the Identity key,
// and it is signed by the Device keychain.
const secretProvider = () => codec.encode(
  createAuthMessage(client.keyring, invitation.swarmKey,
    client.partyManager.identityManager.keyRecord,
    client.partyManager.identityManager.deviceManager.keyChain)
);

const party = await partyManager.joinParty(invitation, secretProvider);

```

This will connect to the Party and issue a `CLAIM` greeting command to the first available
Party member. The member will respond with a new ID for an online invitation and the swarm key
on which to rendezvous to continue the greeting process. From that point, greeting proceeds
as normal, but without any need for manual user intervention (eg, to enter a PIN), since `Auth`
messages signed by the invited key are being used to authenticate the greeting exchange.