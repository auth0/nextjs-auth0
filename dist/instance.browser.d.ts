import { ISignInWithAuth0 } from './instance';
export default function createDummyBrowserInstance(): ISignInWithAuth0 & {
    isBrowser: boolean;
};
