//
// Copyright 2019 DXOS.org
//

import assert from 'assert';
import bufferJson from 'buffer-json-encoding';
import debug from 'debug';
import encode from 'encoding-down';
import levelup from 'levelup';
import memdown from 'memdown';
import toArray from 'stream-to-array';

const log = debug('dxos:creds:keys:keystore'); // eslint-disable-line @typescript-eslint/no-unused-vars

/**
 * LevelDB key storage.
 */
export class KeyStore {
  /**
   * Takes the underlying to DB to use (eg, a leveldown, memdown, etc. instance).
   * If none is specified, memdown is used.
   * @param {LevelDB} [db=memdown()]
   */
  constructor (db) {
    this._db = levelup(encode(db || memdown(), { valueEncoding: bufferJson }));
  }

  /**
   * Adds a KeyRecord to the KeyStore, indexed by `key`.
   * @param {string} key
   * @param {KeyRecord} record
   * @returns {Promise<*>}
   */
  async setRecord (key, record) {
    assert(key);
    assert(record);
    return this._db.put(key, record);
  }

  /**
   * Deletes a KeyRecord from the KeyStore, indexed by `key`.
   * @param {string} key
   * @returns {Promise<*>}
   */
  async deleteRecord (key) {
    assert(key);
    await this._db.del(key);
  }

  /**
   * Looks up a KeyRecord by `key`.
   * @param {string} key
   * @returns {Promise<KeyRecord>}
   */
  async getRecord (key) {
    assert(key);
    return this._db.get(key);
  }

  /**
   * Returns all lookup key strings.
   * @returns {Promise<string[]>}
   */
  async getKeys () {
    return toArray(this._db.createKeyStream({ asBuffer: false }));
  }

  /**
   * Returns all KeyRecord values.
   * @returns {Promise<KeyRecord[]>}
   */
  async getRecords () {
    return toArray(this._db.createValueStream({ asBuffer: false }));
  }

  /**
   * Returns all entries as key/value pairs.
   * @returns {Array.<[string, Object]>}
   */
  async getRecordsWithKey () {
    const entries = await toArray(this._db.createReadStream({ keyAsBuffer: false, valueAsBuffer: false }));
    return entries.map(pair => [pair.key, pair.value]);
  }
}
