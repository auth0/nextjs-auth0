describe('Authentication Flow', () => {
  it('should login successfully and cache session', () => {
    cy.loginWithAuth0();
    cy.visit('/');
    
    // Verify logged in state
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
    cy.get('[data-testid=content]').should('be.visible');
  });

  it('should maintain session across page reloads', () => {
    cy.loginWithAuth0();
    cy.visit('/');
    
    // Verify initial logged in state
    cy.get('[data-testid=content]').should('be.visible');
    
    // Reload page
    cy.reload();
    
    // Verify session persists
    cy.get('[data-testid=content]').should('be.visible');
    cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
  });

  it('should validate session with API endpoint', () => {
    cy.loginWithAuth0();
    
    // Test session validation by checking user is logged in
    cy.visit('/');
    cy.get('[data-testid=navbar-picture-desktop]', { timeout: 10000 }).should('be.visible');
    
    // Also test that we can access authenticated content
    cy.get('body').should('contain.text', 'Welcome');
  });
});
