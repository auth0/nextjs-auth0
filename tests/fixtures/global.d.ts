declare global {
  var getSession: Function | undefined;
  var touchSession: Function | undefined;
  var updateSession: Function | undefined;
  var handleAuth: Function | undefined;
  var withApiAuthRequired: Function | undefined;
  var withPageAuthRequired: Function | undefined;
  var withPageAuthRequiredCSR: Function | undefined;
  var getAccessToken: Function | undefined;
  var asyncProps: boolean | undefined;
  var onError: Function | undefined;
}

export {};
