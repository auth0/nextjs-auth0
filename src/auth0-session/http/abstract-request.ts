export default abstract class AbstractRequest<Req = any> {
  public url: string;
  public method: string;
  public body: Record<string, string>;
  protected constructor(protected req: Req) {
    this.url = this.getUrl();
    this.method = this.getMethod();
    this.body = this.getBody();
  }

  public abstract getUrl(): string;
  public abstract getMethod(): string;
  public abstract getBody(): Record<string, string>;
  public abstract getCookies(): Record<string, string>;
}
