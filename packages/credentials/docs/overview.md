# Credentials Overview
## Design Constraints

1. Users can have multiple "identities".
1. An identity is secured by a "cold" private key (recoverable via a Seed Phrase), which is its root of authority.
1. Identities are associated with a display name (chosen at the point of creation), which cannot be changed.
1. Identities participate in 
multiple parties. To achieve pseudonymity across parties, multiple identities must be used.
1. Devices are associated with an Identity by means of Device Keys that through certification credentials
form a certification DAG for the Identity.
1. Each device needs to have only its own Device Key and keys for its local feeds. No need to have a
master key available on devices for normal operation.
1. Private keys are never exchanged across devices.
1. Devices must be revocable, on the authority of the Identity Key only, with other nodes able to 
determine which feeds and messages from a revoked node should still be considered valid, dating from 
prior to revocation.
1. A new device can be provisioned using any existing device only.
1. The device provisioning process is one-step (once provisioned a new device is 
admitted to all current parties).
1. All a user's devices operate under a single identity for the purposes of access control
in a party.
1. Joining a new party requires user action on only one device. Other devices can automatically
join without user intervention. (Each device may be configured by the user to only replicate a subset of parties).

## Identity
Users, and user-like entities such as Bots are represented by and identified through an Identity Key.
The Identity Key is allows other users to know that a given message they receive is associated with
"Alice" rather than "Alice's Feed" or "Alice's Laptop".

Interactive users create their Identity Key during initial onboarding: "Create New Identity".
After initially signing certification messages that assert the user's name, and authorize the local device
(see device keys below), the Identity Private Key is not retained. 
It must however be saved as a paper key or word phrase, or in 
a secure hardware token for potential later use in device revocation.

Bot Identity Keys are created by the host Bot Container during Bot Instance creation and are securely stored
within the container environment for the lifetime of the Bot Instance.

## Devices
Each device under the control of an identity generates its own Device Key. Devices can certify another
devices using Device Certification Messages, generated as a result of Private Party Greeting (see below). 
The first device is certified by the Identity Key and is the
device on which the Identity Key was created. Devices form a certification DAG with the Identity Key as
its root.

## Identity Hub (change name)
Each Identity has its own "Private Party" called a Hub that operates much like a "Public" Party. 
Its Party Key is the Identity Public Key.
All the user's devices are admitted as members of this party via the PIN-auth Invite/Greet mechanism.
Messages signed by the Identity Key and all Device Certification Messages 
are published on the Hub in order for all devices to have
access to them for re-publishing on Parties. The Hub also allows devices to all know
the set of Parties to which the Identity has been admitted, regardless of which device participated in the
Invite/Greet process.

## Party
Upon admission into a Party, a device publishes the Device Certification Messages for all its siblings,
effectively admitting all the user's current devices into the Party and identifying those devices as under the
control of the Identity Key. Invite/Greeting a device into a Public Party is in effect a certification by the
greeting device, for this Party, of all the admitted Device Keys and Identity Key.
## Device Revocation
Revoking a device requires a trusted root authority, which is the Identity Key. This approach is required 
because if any device were allowed to revoke another it would not be possible to know which devices remain
under the control of the Identity owner and which have been compromised. An attacker might revoke all the
non-compromised devices and thereby take over the Identity. 

Revocation is a "break glass" process involving the loading of the Identity
Private Key from paper storage and subsequent publication of a new set of Device Certification Messages.
In order that the set of post-revocation messages can be distinguished from older messages, in the absence of
trusted timestamps, a generation number
field is included. The messages with the highest generation number should be used.
In order that messages on feeds originating from the revoked devices can be processed appropriately, 
feed termination fields are included in the new Device Certification Message for revoked devices.
These fields specify a set of feed, sequence number tuples that constitute a vector timestamp
for a revoked device, beyond which feed content can not be trusted.

## Bot Instances
Bot Instances only have an Identity Key. They do not have Device Keys: the Identity Key functions as a single Device Key.
Other nodes obtain a Bot Instance's Identity Key from a Bot Container or other query service. Bot admission to
a party is via secure invitation targeting the Identity Key.
