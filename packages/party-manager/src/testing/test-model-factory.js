//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import debug from 'debug';
import pumpify from 'pumpify';
import through from 'through2';

import { keyToBuffer } from '@dxos/crypto';

const log = debug('dxos:party-manager:test:model');

const createMatcher = filter => message => {
  // TODO(burdon): Predicate based filters (e.g., Op.Any(['a', 'b'], 'default')).
  return !Object.keys(filter).some(key => {
    const value = filter[key];
    if (value === undefined) {
      return false;
    }

    // Mismatch is attribute exists but doesn't match regexp.
    if (value instanceof RegExp) {
      return !message[key] || !message[key].match(value);
    }

    // Mistmatch if not attributes match any filter.
    if (Array.isArray(value)) {
      return !value.some(value => message[key] === value);
    }

    // Mismatch if doesn't equal.
    return message[key] !== value;
  });
};

const createFilteredStream = (filter = {}) => {
  const matcher = createMatcher(filter);

  return through.obj(({ data }, encoding, next) => {
    if (matcher(data)) {
      return next(null, data);
    }

    next();
  });
};

/**
 * Simple model factory used to verify party operation without depending on data-client/model
 * Code adapted from data-client original.
 * Model factory creates instances of Model classes and creates a bound Readable stream configured
 * by the model options, and a Writable stream.
 */
export class TestModelFactory {
  /**
   * @param {FeedStore} feedStore
   * @param {PartyWriteStreamProvider} writeStreamProvider
   */
  constructor (feedStore, writeStreamProvider) {
    assert(feedStore);
    assert(writeStreamProvider);

    this._feedStore = feedStore;
    this._writeStreamProvider = writeStreamProvider;
  }

  /**
   * Creates an instance of the model.
   *
   * @param ModelClass
   * @param options {Object}
   * @param options.topic {String}
   * @returns {Promise<Model>}
   */
  async createModel (ModelClass, options = {}) {
    assert(ModelClass);
    log(`Created model: ${ModelClass.name}`);

    const { type, topic, ...rest } = options;

    // TODO(burdon): Option to cache and reference count models.
    const model = new ModelClass();

    //
    // Incoming messages (create read stream).
    //

    const filter = { ...rest };
    if (type) {
      filter.__type_url = type;
    }

    const stream = pumpify.obj(
      this._feedStore.createReadStream({ live: true }),
      createFilteredStream(filter)
    );

    const onData = async (message) => {
      log(`Received: ${JSON.stringify(message)}`);
      if (!model.destroyed) {
        await model.processMessages([message]);
      }
    };

    stream.on('data', onData);

    //
    // Outgoing messages.
    //

    const writeStream = topic ? await this._writeStreamProvider(keyToBuffer(topic)) : undefined;

    const onAppend = (message) => {
      if (writeStream) {
        log(`Writing: ${JSON.stringify(message)}`);
        writeStream.write({ ...message, ...rest });
      }
    };

    model.on('append', onAppend);

    //
    // Clean-up.
    //

    model.once('destroy', model => {
      model.removeListener('append', onAppend);
      stream.removeListener('data', onData);
      // Stream must be closed/destroyed here in order to cleanly close FeedStore later.
      stream.destroy();
    });

    return model;
  }

  // eslint-disable-next-line class-methods-use-this
  destroyModel (model) {
    log('Destroying model');
    model.destroy();
  }
}
