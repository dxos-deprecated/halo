//
// Copyright 2020 DXOS.org
//

import { KeyType } from '../proto/gen/dxos/credentials/party';
export { KeyType };

export const keyTypeName = (keyType: KeyType) => {
  return KeyType[keyType];
};
