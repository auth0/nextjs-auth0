const EMAIL = Cypress.env('USER_EMAIL') || Cypress.env('CYPRESS_USER_EMAIL') || 'a@b.com';
const PASSWORD = Cypress.env('USER_PASSWORD') || Cypress.env('CYPRESS_USER_PASSWORD') || 'Pandeytushar-8';

// Validate environment variables only when needed
function validateCredentials() {
  const email = Cypress.env('USER_EMAIL') || Cypress.env('CYPRESS_USER_EMAIL');
  const password = Cypress.env('USER_PASSWORD') || Cypress.env('CYPRESS_USER_PASSWORD');
  
  if (!email || !password) {
    console.log('Warning: Using fallback credentials. Set CYPRESS_USER_EMAIL and CYPRESS_USER_PASSWORD for production use.');
  }
}

// Auth0 login command with session caching
Cypress.Commands.add('loginWithAuth0', () => {
  validateCredentials(); // Check credentials when actually needed
  cy.session('auth0-session', () => {
    cy.visit('/');
    cy.get('[data-testid=navbar-login-desktop]').click();
    
    // Fill Auth0 login form
    cy.get('input[name=email], input[name=username]').focus().clear().type(EMAIL);
    cy.get('input[name=password]').focus().clear().type(PASSWORD, { log: false });
    cy.get('button[type=submit][name=action]:visible, button[type=submit][name=submit]').click();
    
    // Wait for redirect back to app
    cy.url().should('equal', 'http://localhost:3000/');
    cy.visit('/');
    
    // Verify we're logged in
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
  }, {
    validate: () => {
      // Validate session by checking if user profile is accessible
      cy.visit('/');
      cy.get('[data-testid=navbar-picture-desktop]', { timeout: 10000 }).should('be.visible');
    }
  });
});

// DPoP API testing command
Cypress.Commands.add('testDpopApi', () => {
  cy.get('[data-testid=test-dpop-button]').click();
  cy.get('[data-testid=api-response]').should('be.visible');
});

// Log capture command for debugging
Cypress.Commands.add('captureLogs', () => {
  cy.window().then((win) => {
    win.console.log('Cypress: Capturing console logs');
  });
});

const navbarActiveClass = 'navbar-item-active';

Cypress.Commands.add(
  'isActive',
  {
    prevSubject: true
  },
  selector => {
    cy.get(selector).should('have.class', navbarActiveClass);

    const selectedItems = cy.get('[data-testid=navbar-items]').find('[data-testid|=navbar]');
    if (selectedItems.length > 1) selectedItems.not(selector).should('not.have.class', navbarActiveClass);
  }
);

Cypress.Commands.add('mobileViewport', () => cy.viewport(500, 1000));
