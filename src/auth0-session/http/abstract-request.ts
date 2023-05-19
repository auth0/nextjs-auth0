export default abstract class AbstractRequest<Req = any> {
  protected constructor(public req: Req) {}

  public abstract getUrl(): string;
  public abstract getMethod(): string;
  public abstract getBody(): Promise<Record<string, string> | string> | Record<string, string> | string;
  public abstract getCookies(): Record<string, string>;
}
