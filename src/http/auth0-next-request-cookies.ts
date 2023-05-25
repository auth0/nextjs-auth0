import { cookies } from 'next/headers';
import { Auth0RequestCookies } from '../auth0-session/http';

export default class Auth0NextRequestCookies extends Auth0RequestCookies {
  public constructor() {
    super();
  }

  public getCookies(): Record<string, string> {
    const cookieStore = cookies();
    return cookieStore.getAll().reduce((memo, { name, value }) => ({ ...memo, [name]: value }), {});
  }
}
