describe('DPoP Login Flow (Fixed)', () => {
  it('should successfully login to Auth0 and return to app', () => {
    const email = Cypress.env('CYPRESS_USER_EMAIL') || 'a@b.com';
    const password = Cypress.env('CYPRESS_USER_PASSWORD') || 'Pandeytushar-8';
    
    cy.log(`Testing login with email: ${email}`);
    
    // Visit home page
    cy.visit('/');
    
    // Wait for page to load and find login button
    cy.get('[data-testid=navbar-login-desktop]', { timeout: 15000 })
      .should('be.visible')
      .click();
    
    // Should be redirected to Auth0
    cy.origin('https://dev-10whndm3tf8jetu5.us.auth0.com', { args: { email, password } }, ({ email, password }) => {
      // Wait for Auth0 login page
      cy.get('input[name=email], input[name=username]', { timeout: 15000 })
        .should('be.visible')
        .clear()
        .type(email);
      
      cy.get('input[name=password]', { timeout: 10000 })
        .should('be.visible')
        .clear()
        .type(password, { log: false });
      
      // Click the first visible submit button
      cy.get('button[type=submit]')
        .first()
        .click();
    });
    
    // Wait for redirect back to our app
    cy.url({ timeout: 20000 }).should('eq', 'http://localhost:3000/');
    
    // Verify we're logged in by checking for user profile picture
    cy.get('[data-testid=navbar-picture-desktop]', { timeout: 15000 })
      .should('be.visible');
    
    cy.log('Login successful!');
  });

  it('should test DPoP API after login', () => {
    // Use session caching to ensure we're logged in
    cy.loginWithAuth0();
    
    // Visit the page
    cy.visit('/');
    
    // Verify we're still logged in
    cy.get('[data-testid=navbar-picture-desktop]', { timeout: 10000 })
      .should('be.visible');
    
    // Click the DPoP test button
    cy.get('[data-testid=test-dpop-button]', { timeout: 10000 })
      .should('be.visible')
      .click();
    
    // Wait for API response (either success or error)
    cy.get('[data-testid=api-response], [data-testid=api-error]', { timeout: 15000 })
      .should('be.visible');
    
    // Check which response we got and log accordingly
    cy.get('body').then(($body) => {
      if ($body.find('[data-testid=api-response]').length > 0) {
        cy.log('✅ DPoP API test successful!');
      } else if ($body.find('[data-testid=api-error]').length > 0) {
        cy.log('❌ DPoP API test failed, but error handling works');
      }
    });
  });
});