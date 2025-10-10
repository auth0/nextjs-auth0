describe('Debug Login Flow', () => {
  it('should load the home page and find login button', () => {
    cy.visit('/');
    
    // Debug: Check if page loads
    cy.get('body').should('be.visible');
    // Note: Next.js may not set a default title, so we skip title assertion
    
    // Debug: Check if navbar exists
    cy.get('[data-testid=navbar]').should('be.visible');
    
    // Debug: Take screenshot of initial state
    cy.screenshot('01-initial-page-load');
    
    // Debug: Look for login button
    cy.get('[data-testid=navbar-login-desktop]', { timeout: 10000 })
      .should('be.visible')
      .and('contain', 'Log in');
    
    cy.screenshot('02-login-button-found');
  });

  it('should click login and reach Auth0', () => {
    cy.visit('/');
    
    // Wait for page to load
    cy.get('[data-testid=navbar-login-desktop]').should('be.visible');
    
    // Click login button
    cy.get('[data-testid=navbar-login-desktop]').click();
    
    // Debug: Take screenshot after clicking login
    cy.screenshot('03-after-login-click');
    
    // Should be redirected to Auth0 (domain or login form)
    cy.url({ timeout: 15000 }).should('not.equal', 'http://localhost:3000/');
    
    // Look for Auth0 login form elements
    cy.get('body').should('be.visible');
    cy.screenshot('04-auth0-page');
    
    // Try to find email/username input field
    cy.get('input[name=email], input[name=username], input[type=email]', { timeout: 10000 })
      .should('be.visible');
    
    cy.screenshot('05-auth0-form-found');
  });

  it('should complete login flow with debug info', () => {
    const email = Cypress.env('CYPRESS_USER_EMAIL') || 'a@b.com';
    const password = Cypress.env('CYPRESS_USER_PASSWORD') || 'Pandeytushar-8';
    
    cy.log(`Using email: ${email}`);
    
    cy.visit('/');
    cy.get('[data-testid=navbar-login-desktop]').click();
    
    // Wait for Auth0 page
    cy.get('input[name=email], input[name=username], input[type=email]', { timeout: 15000 })
      .should('be.visible')
      .clear()
      .type(email);
    
    cy.screenshot('06-email-entered');
    
    cy.get('input[name=password], input[type=password]')
      .should('be.visible')
      .clear()
      .type(password, { log: false });
    
    cy.screenshot('07-password-entered');
    
    // Look for submit button (use first match to avoid multiple element error)
    cy.get('button[type=submit], button[name=action], input[type=submit]')
      .first()
      .should('be.visible')
      .click();
    
    cy.screenshot('08-submit-clicked');
    
    // Wait for redirect back to app
    cy.url({ timeout: 20000 }).should('equal', 'http://localhost:3000/');
    
    // Should see user profile picture (logged in state)
    cy.get('[data-testid=navbar-picture-desktop]', { timeout: 10000 })
      .should('be.visible');
    
    cy.screenshot('09-login-success');
  });
});
