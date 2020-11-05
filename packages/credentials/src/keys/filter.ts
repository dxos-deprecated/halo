//
// Copyright 2020 DXOS.org
//

import matches from 'lodash.matches';

import { keyToString } from '@dxos/crypto';

import { PublicKey } from '../typedefs';

export type FilterFuntion = (obj: any) => boolean;

/**
 * Utility to create simple filtering predicates.
 */
export class Filter {
  /**
   * Execute the filter over the supplied values.
   */
  static filter (values: IterableIterator<any>, filter: FilterFuntion) {
    return Array.from(values).filter(value => filter(value));
  }

  /**
   * Negates a filter.
   */
  static not (filter: FilterFuntion): FilterFuntion {
    return value => !filter(value);
  }

  /**
   * ANDs all supplied filters.
   */
  static and (...filters: FilterFuntion[]): FilterFuntion {
    return value => filters.every(filter => filter(value));
  }

  /**
   * Filters objects for required property.
   */
  static hasProperty (property: string): FilterFuntion {
    return ({ [property]: value }) => value !== undefined;
  }

  /**
   * Filters objects for given property values.
   */
  static propertyIn (property: string, values: any[]): FilterFuntion {
    return ({ [property]: value }) => values.includes(value);
  }

  /**
   * Filters objects for required key.
   */
  static hasKey (property: string, key: PublicKey): FilterFuntion {
    const str = keyToString(key);
    return ({ [property]: value }) => keyToString(value) !== str;
  }

  /**
   * Filters objects for exact object.
   * https://lodash.com/docs/#matches
   */
  static matches (attributes: any): FilterFuntion {
    return matches(attributes);
  }
}
