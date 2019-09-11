/// <reference types="node" />
import { IncomingMessage, ServerResponse } from 'http';
interface ICookies {
    [key: string]: string;
}
interface ICookie {
    /**
     * The name of the cookie.
     */
    name: string;
    /**
     *  The value of the cookie.
     */
    value: string;
    /**
     * The maximum age of the cookie in milliseconds.
     */
    maxAge: number;
    /**
     * The path of the cookie
     */
    path?: string;
}
/**
 * Parses the cookies from an API Route or from Pages and returns a key/value object containing all the cookies.
 * @param req Incoming HTTP request.
 */
export declare function parseCookies(req: IncomingMessage): ICookies;
/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 */
export declare function setCookies(res: ServerResponse, cookies: Array<ICookie>): void;
/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 */
export declare function setCookie(res: ServerResponse, cookie: ICookie): void;
export {};
