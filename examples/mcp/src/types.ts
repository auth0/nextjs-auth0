import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export interface Auth extends AuthInfo {
  extra: {
    sub: string;
    client_id?: string;
    azp?: string;
    name?: string;
    email?: string;
  };
}
