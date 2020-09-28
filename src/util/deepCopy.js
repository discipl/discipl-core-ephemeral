import * as cloneDeep from 'lodash.clonedeep'

function deepCopy (value) {
  return cloneDeep.default(value)
}

export { deepCopy }
