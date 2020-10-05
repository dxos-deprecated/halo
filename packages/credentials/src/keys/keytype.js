//
// Copyright 2020 DXOS.org
//

import { KeyType } from '../proto/gen/dxos/credentials/party'
export { KeyType }

export const keyTypeName = (keyType) => {
  for (const type of Object.keys(KeyType)) {
    if (KeyType[type] === keyType) {
      return type;
    }
  }
  return undefined;
};
