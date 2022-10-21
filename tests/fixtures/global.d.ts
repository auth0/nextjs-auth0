declare global {
  namespace NodeJS {
    interface Global {
      getSession?: Function;
      updateSession?: Function;
      handleAuth?: Function;
      withApiAuthRequired?: Function;
      withPageAuthRequired?: Function;
      withPageAuthRequiredCSR?: Function;
      getAccessToken?: Function;
      asyncProps?: boolean;
      onError?: Function;
    }
  }
}

export {};
