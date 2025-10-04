describe('logged out', () => {
  beforeEach(() => cy.visit('/'));

  context('desktop', () => {
    it('should display the navigation bar', () => {
      cy.get('[data-testid=navbar]').should('be.visible');
      cy.get('[data-testid=navbar-items]').should('be.visible');
      cy.get('[data-testid=navbar-login-desktop]').should('be.visible');
      cy.get('[data-testid=navbar-login-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-toggle]').should('not.be.visible');
    });

    it('should display the footer', () => {
      cy.get('[data-testid=footer]').should('be.visible');
    });

    it('should display the home page', () => {
      cy.get('[data-testid=navbar-home]').click();
      cy.url().should('eq', `${Cypress.config().baseUrl}/`);

      cy.get('[data-testid=navbar-home]').isActive();
      cy.get('[data-testid=hero]').should('be.visible');
      cy.get('[data-testid=content]').should('be.visible');
    });
  });

  context('mobile', () => {
    beforeEach(() => cy.mobileViewport());

    it('should expand the navigation bar menu', () => {
      cy.get('[data-testid=navbar-items]').should('not.be.visible');
      cy.get('[data-testid=navbar-login-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-login-desktop]').should('not.be.visible');
      cy.get('[data-testid=navbar-toggle]').should('be.visible');
      cy.get('[data-testid=navbar-toggle]').click();
      cy.get('[data-testid=navbar-items]').should('be.visible');
      cy.get('[data-testid=navbar-login-mobile]').should('be.visible');
      cy.get('[data-testid=navbar-login-desktop]').should('not.be.visible');
    });
  });
});
