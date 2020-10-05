// TODO(marik-d): Workaround to avoid name colisions in generated files.
//
// Copyright 2020 DXOS.org
//

import { Schema as CodecSchema } from '@dxos/codec-experimental-runtime';

import { DecodedAny } from './any';

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
    decode: (value: any, schema: CodecSchema<any>): DecodedAny => {
      const codec = schema.tryGetCodecForType(value.type_url);
      const data = codec.decode(value.value);
      return {
        ...data,
        __type_url: value.type_url
      };
    }
  }
};
