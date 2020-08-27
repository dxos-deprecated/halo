//
// Copyright 2020 DXOS.org
//

import { codec } from '../proto';

/**
 * Constants
 */
export const Command = {
  Type: Object.freeze({
    ...codec.getType('dxos.halo.credentials.greet.Command.Type').values
  })
};
