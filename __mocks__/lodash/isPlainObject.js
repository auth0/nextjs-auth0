'use strict';

// From https://github.com/sindresorhus/is-plain-obj/blob/v2.1.0/index.js
// As this one is more permissive and works on Edge runtime
module.exports = (value) => {
  if (Object.prototype.toString.call(value) !== '[object Object]') {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
};
