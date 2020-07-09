//
// Copyright 2019 DXOS.org
//

// Simple Model used to verify party operation without depending on data-client/model
// Code adapted from data-client original.

import EventEmitter from 'events';

import { createId, humanize } from '@dxos/crypto';

/**
 * HOC (withModel) ==> ModelFactory => Model <=> App
 *                 \=> Feed <==========/
 *
 * Events: `append`, `update`, `destroy`
 */
export class TestModel extends EventEmitter {
  _messages = [];

  constructor () {
    super();

    this._id = createId();
    this._destroyed = false;
  }

  get id () {
    return humanize(this._id);
  }

  get destroyed () {
    return this._destroyed;
  }

  destroy () {
    this._destroyed = true;
    this.onDestroy();
    this.emit('destroy', this);
  }

  async processMessages (messages) {
    await this.onUpdate(messages);
    this.emit('update', this);
  }

  // TODO(burdon): appendMessages.
  appendMessage (message) {
    this.emit('append', message);
  }

  get messages () {
    return this._messages;
  }

  async onUpdate (messages) {
    this._messages.push(...messages);
  }

  // TODO(burdon): Async?
  // eslint-disable-next-line
  onDestroy() {}
}
