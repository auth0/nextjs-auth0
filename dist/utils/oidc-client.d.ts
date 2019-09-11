import IAuth0Settings from '../settings';
export interface IOidcClientFactory {
    (): Promise<any>;
}
export default function getClient(settings: IAuth0Settings): IOidcClientFactory;
