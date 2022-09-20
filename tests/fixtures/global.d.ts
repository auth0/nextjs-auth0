declare global {
  namespace NodeJS {
    interface Global {
      getSession?: Function;
      updateUser?: Function;
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
