import { Auth0RequestCookies } from '../auth0-session/http';

export default class Auth0NextRequestCookies extends Auth0RequestCookies {
  public constructor() {
    super();
  }

  public getCookies(): Record<string, string> {
    const { cookies } = require('next/headers');
    const cookieStore = cookies();
    return cookieStore.getAll().reduce(
      (memo: Record<string, string>, { name, value }: { name: string; value: string }) => ({
        ...memo,
        [name]: value
      }),
      {}
    );
  }
}
