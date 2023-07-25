export default abstract class Auth0RequestCookies {
  public abstract getCookies(): Record<string, string>;
}
