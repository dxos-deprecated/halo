//
// Copyright 2019 DxOS
//

import assert from 'assert';
import CryptoJS from 'crypto-js';

import { trigger, promiseTimeout, sleep } from '@dxos/async';

/**
 * Returns a Promise which resolves when `condFn` returns truthy. They value returned by
 * `condFn` is used to resolve the Promise.
 * @param {function} condFn
 * @param {number} [timeout] How long to wait, in milliseconds (0 = no timeout).
 * @param {number} [interval=10] How frequently to check, in milliseconds.
 * @returns {*}
 */
// TODO(telackey): Add to @dxos/async
export const waitForCondition = (condFn, timeout = 0, interval = 10) => {
  assert(condFn);
  assert(interval > 0);

  const stopTime = timeout ? Date.now() + timeout : 0;
  const [provider, resolver] = trigger();
  const waiter = async () => {
    // eslint-disable-next-line no-unmodified-loop-condition
    while (!stopTime || Date.now() < stopTime) {
      try {
        const value = condFn();
        if (value) {
          resolver(value);
          break;
        }
      } catch (e) {
        // pass...
      }
      // eslint-disable-next-line no-await-in-loop
      await sleep(interval);
    }
  };
  setTimeout(waiter, 0);

  return timeout ? promiseTimeout(provider(), timeout) : provider();
};

// TODO(telackey): Remove when the published version of '@dxos/crypto' has this.
export const ripemd160 = (plaintext) => {
  assert(typeof plaintext === 'string');

  return CryptoJS.RIPEMD160(plaintext).toString();
};
