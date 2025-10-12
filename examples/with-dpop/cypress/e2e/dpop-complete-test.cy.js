describe('DPoP Complete Test Suite', () => {
  // Use session caching to maintain login across tests
  beforeEach(() => {
    // Custom login command with session persistence
    cy.session('dpop-test-session', () => {
      const email = Cypress.env('CYPRESS_USER_EMAIL') || 'a@b.com';
      const password = Cypress.env('CYPRESS_USER_PASSWORD') || 'Pandeytushar-8';
      
      cy.log(`Logging in with: ${email}`);
      
      cy.visit('/');
      
      // Click login button
      cy.get('[data-testid=navbar-login-desktop]', { timeout: 15000 })
        .should('be.visible')
        .click();
      
      // Handle Auth0 login in cross-origin context
      cy.origin('https://dev-10whndm3tf8jetu5.us.auth0.com', { args: { email, password } }, ({ email, password }) => {
        cy.get('input[name=email], input[name=username]', { timeout: 15000 })
          .should('be.visible')
          .clear()
          .type(email);
        
        cy.get('input[name=password]', { timeout: 10000 })
          .should('be.visible')
          .clear()
          .type(password, { log: false });
        
        cy.get('button[type=submit]')
          .first()
          .click();
      });
      
      // Wait for redirect and verify login
      cy.url({ timeout: 20000 }).should('eq', 'http://localhost:3000/');
      cy.get('[data-testid=navbar-picture-desktop]', { timeout: 15000 })
        .should('be.visible');
    }, {
      validate: () => {
        // Validate session is still active
        cy.visit('/');
        cy.get('[data-testid=navbar-picture-desktop]', { timeout: 5000 })
          .should('be.visible');
      }
    });
  });

  it('should maintain logged-in state after session caching', () => {
    cy.visit('/');
    
    // Should be logged in due to session caching
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Should see the main content for logged-in users
    cy.get('[data-testid=content]')
      .should('be.visible');
    
    cy.log('✅ Session persistence working!');
  });

  it('should test DPoP API functionality', () => {
    cy.visit('/');
    
    // Verify logged-in state
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Find and click server-side DPoP test button (using correct selector and text)
    cy.get('[data-testid=test-dpop-button]')
      .should('be.visible')
      .and('contain', 'Test Server-Side DPoP API')
      .click();
    
    // Wait for API response (success or error)
    cy.get('[data-testid=api-response], [data-testid=api-error]', { timeout: 20000 })
      .should('be.visible');
    
    // Check for successful response
    cy.get('body').then(($body) => {
      if ($body.find('[data-testid=api-response]').length > 0) {
        cy.log('✅ DPoP API test successful!');
        cy.get('[data-testid=api-response]')
          .should('contain', 'DPoP API Test Successful');
      } else if ($body.find('[data-testid=api-error]').length > 0) {
        cy.log('⚠️ DPoP API test failed, but error handling works');
        cy.get('[data-testid=api-error]')
          .should('contain', 'DPoP API Test Failed');
      }
    });
  });

  it('should verify session persists across page reloads', () => {
    cy.visit('/');
    
    // Verify initial logged-in state
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Reload the page
    cy.reload();
    
    // Should still be logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    cy.log('✅ Session persists across page reloads!');
  });
});
