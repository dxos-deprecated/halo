//
// Copyright 2020 DXOS.org
//

// eslint-disable-next-line camelcase
export type WithTypeUrl<T> = T & { __type_url: string }

export interface DecodedAny {
  // eslint-disable-next-line camelcase
  __type_url: string,
  [key: string]: any,
}
