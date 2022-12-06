import React from 'react';

if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  const whyDidYouRender = require('@welldone-software/why-did-you-render');
  whyDidYouRender(React, {
    trackAllPureComponents: true,
    trackHooks: true,
    logOwnerReasons: true,
  });
}
