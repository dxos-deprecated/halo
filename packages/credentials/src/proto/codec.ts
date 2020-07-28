//
// Copyright 2019 DXOS.org
//

import { Codec } from '@dxos/codec-protobuf';

import Defs from './gen/bundle.json';

// TODO(burdon): Common system-wide codec.
export const codec = new Codec('dxos.credentials.Message')
  .addJson(Defs)
  .build();

// TODO(dboreham): what is this validating and why would the caller be calling it?
export const validate = (message: any) => codec.decode(codec.encode(message));

export { dxos } from './gen/bundle'