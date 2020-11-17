//
// Copyright 2020 DXOS.org
//

import { Schema as CodecSchema } from '@dxos/codec-protobuf';
import { PublicKey } from '@dxos/crypto';

import { KeyRecord } from '../keys/keyrecord';
import { DecodedAny, KnownAny } from './any';

export default {
  'google.protobuf.Any': {
    encode: (value: DecodedAny, schema: CodecSchema<any>) => {
      const codec = schema.tryGetCodecForType(value.__type_url);
      const data = codec.encode(value);
      return {
        type_url: value.__type_url,
        value: data
      };
    },
    decode: (value: any, schema: CodecSchema<any>): KnownAny => {
      const codec = schema.tryGetCodecForType(value.type_url);
      const data = codec.decode(value.value);
      return {
        ...data,
        __type_url: value.type_url
      };
    }
  },
  'dxos.credentials.keys.Key': {
    encode: (value: KeyRecord) => {
      return {
        ...value,
        publicKey: PublicKey.from(value.publicKey).asUint8Array()
      };
    },
    decode: (value: any): KeyRecord => {
      return {
        ...value,
        publicKey: PublicKey.from(value.publicKey),
        secretKey: value.secretKey ? Buffer.from(value.secretKey) : undefined
      };
    }
  }
};
