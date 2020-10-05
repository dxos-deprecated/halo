//
// Copyright 2019 DXOS.org
//

import { schemaJson as Schema, schema } from './gen';

export const codec = schema.getCodecForType('dxos.credentials.Message');

// TODO(dboreham): what is this validating and why would the caller be calling it?
export const validate = (message: any) => codec.decode(codec.encode(message));

export { Schema, schema };
