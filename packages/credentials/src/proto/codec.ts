//
// Copyright 2019 DXOS.org
//

import { Codec } from '@dxos/codec-protobuf';

import { schemaJson as Schema, schema } from './gen';

// TODO(burdon): Common system-wide codec.
export const codec = new Codec('dxos.credentials.Message')
  .addJson(Schema)
  .build();

// TODO(dboreham): what is this validating and why would the caller be calling it?
export const validate = (message: any) => codec.decode(codec.encode(message));

export { Schema, schema };
