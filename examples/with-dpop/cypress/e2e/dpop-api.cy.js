describe('DPoP Authentication and API Testing', () => {
  beforeEach(() => {
    // Use session-cached login to avoid repeated Auth0 flows
    cy.loginWithAuth0();
    cy.visit('/');
  });

  it('should display the DPoP example page with user logged in', () => {
    cy.get('[data-testid=hero]').should('be.visible');
    cy.get('[data-testid=hero-title]').should('contain', 'DPoP');
    cy.get('[data-testid=content]').should('be.visible');
    cy.get('[data-testid=test-dpop-button]').should('be.visible');
  });

  it('should successfully test DPoP API and display response', () => {
    // Capture console logs for debugging
    cy.window().then((win) => {
      cy.stub(win.console, 'log').as('consoleLog');
      cy.stub(win.console, 'error').as('consoleError');
    });

    // Click the DPoP test button
    cy.get('[data-testid=test-dpop-button]').click();
    
    // Wait for API response (with generous timeout for DPoP processing)
    cy.get('[data-testid=api-response]', { timeout: 10000 }).should('be.visible');
    
    // Verify successful response content
    cy.get('[data-testid=api-response]').within(() => {
      cy.contains('DPoP API Test Successful!').should('be.visible');
      cy.contains('DPoP Enabled: Yes').should('be.visible');
      cy.contains('Token Claims:').should('be.visible');
    });

    // Verify no error response is shown
    cy.get('[data-testid=api-error]').should('not.exist');

    // Check that console logs indicate successful DPoP flow
    cy.get('@consoleLog').should('have.been.called');
  });

  it('should handle API errors gracefully', () => {
    // Intercept the API call to simulate an error
    cy.intercept('GET', '/api/shows', { 
      statusCode: 500, 
      body: { error: 'Simulated server error' } 
    }).as('apiError');

    cy.get('[data-testid=test-dpop-button]').click();
    cy.wait('@apiError');
    
    // Verify error is displayed
    cy.get('[data-testid=api-error]', { timeout: 5000 }).should('be.visible');
    cy.get('[data-testid=api-error]').should('contain', 'DPoP API Test Failed');
    
    // Verify success response is not shown
    cy.get('[data-testid=api-response]').should('not.exist');
  });

  it('should maintain session across multiple API calls', () => {
    // First API call
    cy.get('[data-testid=test-dpop-button]').click();
    cy.get('[data-testid=api-response]', { timeout: 10000 }).should('be.visible');
    
    // Clear previous response by refreshing
    cy.reload();
    
    // Second API call should work without re-authentication
    cy.get('[data-testid=test-dpop-button]').click();
    cy.get('[data-testid=api-response]', { timeout: 10000 }).should('be.visible');
  });

  it('should show loading state during API call', () => {
    // Intercept API call to add delay
    cy.intercept('GET', '/api/shows', (req) => {
      req.reply(() => {
        // Add 2 second delay and return success fixture
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve({
              statusCode: 200,
              body: {
                msg: "This is a DPoP-protected API!",
                dpopEnabled: true,
                claims: {
                  iss: "https://test-domain.auth0.com/",
                  sub: "test-user-123"
                }
              }
            });
          }, 2000);
        });
      });
    }).as('slowApi');

    cy.get('[data-testid=test-dpop-button]').click();
    
    // Verify loading state (server-side button)
    cy.get('[data-testid=test-dpop-button]').should('contain', 'Testing Server DPoP API...');
    cy.get('[data-testid=test-dpop-button]').should('be.disabled');
    
    cy.wait('@slowApi');
    
    // Verify loading state clears
    cy.get('[data-testid=test-dpop-button]').should('contain', 'Test Server-Side DPoP API');
    cy.get('[data-testid=test-dpop-button]').should('not.be.disabled');
  });
});
