import { NodeResponse } from '../auth0-session/http';
import { NextApiResponse } from 'next';

export default class Auth0NextApiResponse extends NodeResponse<NextApiResponse> {
  public redirect(location: string, status = 302): void {
    if (this.res.writableEnded) {
      return;
    }
    this.res.redirect(status, (this.res.getHeader('Location') as string) || location);
  }
}
