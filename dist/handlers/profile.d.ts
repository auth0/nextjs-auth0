import { NextApiResponse, NextApiRequest } from 'next';
import { ISessionStore } from '../session/store';
export default function profileHandler(sessionStore: ISessionStore): (req: NextApiRequest, res: NextApiResponse<any>) => Promise<void>;
