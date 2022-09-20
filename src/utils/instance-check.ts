let isUsingNamedExports = false;
let isUsingOwnInstance = false;

const instanceCheck = () => {
  if (isUsingNamedExports && isUsingOwnInstance) {
    throw new Error(
      'You cannot mix creating your own instance with `initAuth0` and using named ' +
        "exports like `import { handleAuth } from '@auth0/nextjs-auth0'`"
    );
  }
};

export const setIsUsingNamedExports = (): void => {
  isUsingNamedExports = true;
  instanceCheck();
};

export const setIsUsingOwnInstance = (): void => {
  isUsingOwnInstance = true;
  instanceCheck();
};
