import type { AppProps } from "next/app";
import { Auth0Provider } from "@auth0/nextjs-auth0";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <Auth0Provider user={pageProps.user}>
      <Component {...pageProps} />
    </Auth0Provider>
  );
}
