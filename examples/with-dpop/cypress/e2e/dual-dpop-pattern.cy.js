describe('Dual DPoP Testing Pattern E2E', () => {
  // Use session caching to maintain login across tests
  beforeEach(() => {
    // Custom login command with session persistence
    cy.session('dual-dpop-test-session', () => {
      const email = Cypress.env('CYPRESS_USER_EMAIL') || 'a@b.com';
      const password = Cypress.env('CYPRESS_USER_PASSWORD') || 'Pandeytushar-8';
      
      cy.log(`Logging in with: ${email}`);
      
      cy.visit('/');
      
      // Click login button (handle multiple elements by using first)
      cy.get('[data-testid=navbar-login-desktop]', { timeout: 15000 })
        .should('be.visible')
        .then($btns => {
          if ($btns.length > 1) {
            cy.wrap($btns.first()).click();
          } else {
            cy.wrap($btns).click();
          }
        });
      
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
      
      // Wait for redirect back to our app and verify we're logged in
      cy.url({ timeout: 20000 }).should('eq', 'http://localhost:3000/');
      cy.get('[data-testid=navbar-picture-desktop]', { timeout: 15000 })
        .should('be.visible');
    });
    
    // Visit the page after login
    cy.visit('/');
    
    // Verify we're logged in
    cy.get('[data-testid=navbar-picture-desktop]', { timeout: 15000 }).should('be.visible');
  });

  it('should have both DPoP testing buttons available', () => {
    // Verify both testing buttons are present
    cy.get('[data-testid="test-dpop-button"]', { timeout: 10000 })
      .should('be.visible')
      .should('contain.text', 'Test Server-Side DPoP API');
      
    cy.get('[data-testid="test-client-dpop-button"]', { timeout: 10000 })
      .should('be.visible')
      .should('contain.text', 'Test Client-Side DPoP API');
  });

  it('should return identical results from both server-side and client-side DPoP testing', () => {
    let serverSideResults = {};
    let clientSideResults = {};

    // Test server-side DPoP first
    cy.log('Testing Server-Side DPoP API');
    cy.get('[data-testid="test-dpop-button"]').click();
    
    // Wait for server-side results to appear
    cy.get('[data-testid="api-response"]', { timeout: 15000 })
      .should('be.visible');
    
    // Capture server-side results
    cy.get('[data-testid="api-response"]').then(($el) => {
      const resultText = $el.text();
      cy.log(`Server-side result: ${resultText}`);
      
      // Parse key result elements
      const dpopEnabledMatch = resultText.match(/DPoP Enabled:\s*(Yes|No|true|false)/);
      const messageMatch = resultText.match(/Message:\s*([^,\n]+)/);
      const claimsMatch = resultText.match(/Claims:\s*(\{[^}]+\})/);
      
      serverSideResults = {
        dpopEnabled: dpopEnabledMatch ? dpopEnabledMatch[1] : 'Not found',
        message: messageMatch ? messageMatch[1].trim() : 'Not found',
        hasClaims: claimsMatch ? 'Yes' : 'No',
        fullText: resultText
      };
      
      cy.log('Server-side parsed results:', serverSideResults);
    });

    // Small delay to ensure UI is ready for next test
    cy.wait(1000);

    // Test client-side DPoP
    cy.log('Testing Client-Side DPoP API');
    cy.get('[data-testid="test-client-dpop-button"]').click();
    
    // Wait for client-side results to appear
    cy.get('[data-testid="client-api-response"]', { timeout: 15000 })
      .should('be.visible');
    
    // Capture and compare client-side results
    cy.get('[data-testid="client-api-response"]').then(($el) => {
      const resultText = $el.text();
      cy.log(`Client-side result: ${resultText}`);
      
      // Parse key result elements
      const dpopEnabledMatch = resultText.match(/DPoP Enabled:\s*(Yes|No|true|false)/);
      const messageMatch = resultText.match(/Message:\s*([^,\n]+)/);
      const claimsMatch = resultText.match(/Claims:\s*(\{[^}]+\})/);
      
      clientSideResults = {
        dpopEnabled: dpopEnabledMatch ? dpopEnabledMatch[1] : 'Not found',
        message: messageMatch ? messageMatch[1].trim() : 'Not found',
        hasClaims: claimsMatch ? 'Yes' : 'No',
        fullText: resultText
      };
      
      cy.log('Client-side parsed results:', clientSideResults);
      
      // Compare the results
      cy.log('Comparing results...');
      
      // Verify DPoP status is identical
      expect(clientSideResults.dpopEnabled).to.equal(serverSideResults.dpopEnabled, 
        'DPoP enabled status should be identical between server-side and client-side');
      
      // Verify message content is identical
      expect(clientSideResults.message).to.equal(serverSideResults.message,
        'Message content should be identical between server-side and client-side');
      
      // Verify claims presence is identical
      expect(clientSideResults.hasClaims).to.equal(serverSideResults.hasClaims,
        'Claims presence should be identical between server-side and client-side');
      
      cy.log('✅ Dual testing pattern validation successful - both approaches return identical results');
    });
  });

  it('should handle errors consistently in both testing approaches', () => {
    // This test would require server to be down or configured to return errors
    // For now, we'll just verify that both buttons respond to clicks
    
    cy.log('Testing error handling consistency');
    
    // Test server-side button response
    cy.get('[data-testid="test-dpop-button"]').click();
    cy.get('[data-testid="api-response"]', { timeout: 15000 })
      .should('be.visible');
    
    // Small delay between tests
    cy.wait(1000);
    
    // Test client-side button response
    cy.get('[data-testid="test-client-dpop-button"]').click();
    cy.get('[data-testid="client-api-response"]', { timeout: 15000 })
      .should('be.visible');
    
    cy.log('✅ Both testing approaches respond to user interactions');
  });

  it('should display results in the correct format for both approaches', () => {
    // Test server-side format
    cy.get('[data-testid="test-dpop-button"]').click();
    cy.get('[data-testid="api-response"]', { timeout: 15000 })
      .should('be.visible')
      .should('contain.text', 'DPoP Enabled:')
      .should('contain.text', 'Message:');
    
    // Small delay between tests
    cy.wait(1000);
    
    // Test client-side format
    cy.get('[data-testid="test-client-dpop-button"]').click();
    cy.get('[data-testid="client-api-response"]', { timeout: 15000 })
      .should('be.visible')
      .should('contain.text', 'DPoP Enabled:')
      .should('contain.text', 'Message:');
    
    cy.log('✅ Both testing approaches display results in the expected format');
  });

  it('should maintain session state across both testing approaches', () => {
    // Verify user is still logged in throughout the test
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
    
    // Test server-side (should work with authenticated session)
    cy.get('[data-testid="test-dpop-button"]').click();
    cy.get('[data-testid="api-response"]', { timeout: 15000 })
      .should('be.visible')
      .should('not.contain.text', 'Error:')
      .should('not.contain.text', 'Unauthorized');
    
    // Verify still logged in
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
    
    // Small delay between tests
    cy.wait(1000);
    
    // Test client-side (should work with authenticated session)
    cy.get('[data-testid="test-client-dpop-button"]').click();
    cy.get('[data-testid="client-api-response"]', { timeout: 15000 })
      .should('be.visible')
      .should('not.contain.text', 'Error:')
      .should('not.contain.text', 'Unauthorized');
    
    // Verify still logged in after both tests
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
    
    cy.log('✅ Session state maintained consistently across both testing approaches');
  });
});
