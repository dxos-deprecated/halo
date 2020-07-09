//
// Copyright 2019 DXOS.org
//

import { Codec } from '@dxos/codec-protobuf';

import AuthDefs from './gen/auth.json';
import GreetDefs from './gen/greet.json';
import IdentityDefs from './gen/identity.json';
import PartyDefs from './gen/party.json';
import SignedDefs from './gen/signed.json';

// TODO(burdon): Common system-wide codec.
export const codec = new Codec('dxos.credentials.Message')
  .addJson(AuthDefs)
  .addJson(GreetDefs)
  .addJson(IdentityDefs)
  .addJson(PartyDefs)
  .addJson(SignedDefs)
  .build();

// TODO(dboreham): what is this validating and why would the caller be calling it?
export const validate = (message) => codec.decode(codec.encode(message));
