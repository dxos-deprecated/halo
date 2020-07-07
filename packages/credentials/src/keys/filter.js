//
// Copyright 2020 DXOS.org
//

import matches from 'lodash.matches';

import { keyToString } from '@dxos/crypto';

/**
 * Utility to create simple filtering predicates.
 */
export class Filter {
  /**
   * Execute the filter over the supplied values.
   * @param {Object} values
   * @param {Function} filter
   * @returns {Object}
   */
  static filter (values, filter) {
    return Array.from(values).filter(value => filter(value));
  }

  /**
   * Negates a filter.
   * @param {Function} filter
   * @returns {Function}
   */
  static not (filter) {
    return value => !filter(value);
  }

  /**
   * ANDs all supplied filters.
   * @param {Function[]} filters
   * @returns {Function}
   */
  static and (...filters) {
    return value => filters.every(filter => filter(value));
  }

  /**
   * Filters objects for required property.
   * @param {string} property
   * @returns {Function}
   */
  static hasProperty (property) {
    return ({ [property]: value }) => value !== undefined;
  }

  /**
   * Filters objects for given property values.
   * @param {string} property
   * @param {any[]} values
   * @returns {Function}
   */
  static propertyIn (property, values) {
    return ({ [property]: value }) => values.includes(value);
  }

  /**
   * Filters objects for required key.
   * @param {string} property
   * @param {KeyPair} key
   * @returns {Function}
   */
  static hasKey (property, key) {
    const str = keyToString(key);
    return ({ [property]: value }) => keyToString(value) !== str;
  }

  /**
   * Filters objects for exact object.
   * https://lodash.com/docs/#matches
   * @param {Object} attributes
   * @returns {Function}
   */
  static matches (attributes) {
    return matches(attributes);
  }
}
