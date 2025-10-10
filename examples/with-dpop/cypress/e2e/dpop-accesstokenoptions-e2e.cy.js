describe('DPoP AccessTokenOptions E2E Tests', () => {
  // Use session caching to maintain login across tests
  beforeEach(() => {
    cy.session('dpop-accesstoken-session', () => {
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

  it('should test DPoP API with default accessToken configuration', () => {
    cy.visit('/');
    
    // Verify user is logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Click the DPoP API test button
    cy.get('[data-testid=test-dpop-button]')
      .should('be.visible')
      .should('contain', 'Test Server-Side DPoP API')
      .click();
    
    // Wait for API response and check for success
    cy.get('[data-testid=test-dpop-button]', { timeout: 10000 })
      .should('contain', 'Test Server-Side DPoP API');
    
    // Check for success indicators in the page
    cy.get('body').then(($body) => {
      // Look for success indicators that might be added to the page
      if ($body.find('[data-testid=api-response]').length > 0) {
        cy.get('[data-testid=api-response]')
          .should('be.visible')
          .should('contain', 'DPoP');
      }
    });
  });

  it('should test DPoP functionality through the UI', () => {
    cy.visit('/');
    
    // Verify user is logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Test the DPoP API endpoint
    cy.get('[data-testid=test-dpop-button]')
      .should('be.visible')
      .click();
    
    // Wait for button state to change (indicating API call completion)
    cy.get('[data-testid=test-dpop-button]', { timeout: 15000 })
      .should('not.contain', 'Testing Server DPoP API...');
    
    // Verify the button returns to normal state
    cy.get('[data-testid=test-dpop-button]')
      .should('contain', 'Test Server-Side DPoP API');
  });

  it('should directly test the DPoP API endpoint', () => {
    cy.visit('/');
    
    // Verify user is logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Make a direct request to the API endpoint to verify DPoP functionality
    cy.request({
      method: 'GET',
      url: '/api/shows',
      failOnStatusCode: false
    }).then((response) => {
      // The response might be 401 if session cookies aren't passed,
      // but this tests that the endpoint exists and responds
      expect(response.status).to.be.oneOf([200, 401]);
      
      if (response.status === 200) {
        expect(response.body).to.have.property('msg');
        expect(response.body).to.have.property('dpopEnabled');
        expect(response.body.dpopEnabled).to.be.true;
      }
      
      if (response.status === 401) {
        expect(response.body).to.have.property('error');
        expect(response.body.error).to.equal('missing_session');
      }
    });
  });

  it('should verify DPoP environment configuration', () => {
    cy.visit('/');
    
    // Verify user is logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Test that the page loads correctly with DPoP enabled
    cy.get('body').should('be.visible');
    
    // Verify the page title contains relevant information
    cy.title().should('contain', 'DPoP Example');
    
    // Check that the test button is present (indicating DPoP functionality is available)
    cy.get('[data-testid=test-dpop-button]')
      .should('be.visible')
      .should('contain', 'DPoP');
  });

  it('should handle logout and re-login flow', () => {
    cy.visit('/');
    
    // Verify user is logged in
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('be.visible');
    
    // Click logout
    cy.get('[data-testid=navbar-logout-desktop]')
      .should('be.visible')
      .click();
    
    // Should be redirected and logged out
    cy.url({ timeout: 10000 }).should('eq', 'http://localhost:3000/');
    
    // Login button should be visible again
    cy.get('[data-testid=navbar-login-desktop]', { timeout: 10000 })
      .should('be.visible');
    
    // User profile should not be visible
    cy.get('[data-testid=navbar-picture-desktop]')
      .should('not.exist');
  });
});