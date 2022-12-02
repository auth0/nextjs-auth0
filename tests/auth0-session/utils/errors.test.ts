import { IdentityProviderError } from '../../../src';

describe('IdentityProviderError', () => {
  test('should escape error fields', () => {
    const error = new IdentityProviderError({
      name: 'RPError',
      message: "<script>alert('foo')</script>",
      error: "<script>alert('foo')</script>",
      error_description: "<script>alert('foo')</script>"
    });

    expect(error.message).toEqual('&lt;script&gt;alert(&#39;foo&#39;)&lt;/script&gt;');
    expect(error.error).toEqual('&lt;script&gt;alert(&#39;foo&#39;)&lt;/script&gt;');
    expect(error.errorDescription).toEqual('&lt;script&gt;alert(&#39;foo&#39;)&lt;/script&gt;');
  });
});
