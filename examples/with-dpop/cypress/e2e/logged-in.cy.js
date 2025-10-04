const EMAIL = Cypress.env('USER_EMAIL');
const PASSWORD = Cypress.env('USER_PASSWORD');

if (!EMAIL || !PASSWORD) {
  throw new Error('You must provide CYPRESS_USER_EMAIL and CYPRESS_USER_PASSWORD environment variables');
}

const login = () => {
  cy.get('input[name=email], input[name=username]').focus().clear().type(EMAIL);
  cy.get('input[name=password]').focus().clear().type(PASSWORD, { log: false });
  cy.get('button[type=submit][name=action]:visible, button[type=submit][name=submit]').click();
  cy.url().should('equal', 'http://localhost:3000/');
  cy.visit('/');
};

describe('logged in', () => {
  context('desktop', () => {
    beforeEach(() => {
      cy.visit('/');
      cy.get('[data-testid=navbar-login-desktop]').click();
      login();
    });

    it('should display the navigation bar', () => {
      cy.get('[data-testid=navbar]').should('be.visible');
      cy.get('[data-testid=navbar-items]').should('be.visible');
      cy.get('[data-testid=navbar-menu-desktop]').should('be.visible');
      cy.get('[data-testid=navbar-menu-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-picture-desktop]').should('be.visible');
      cy.get('[data-testid=navbar-picture-mobile]').should('not.be.visible');
    });

    it('should expand the navigation bar menu', () => {
      cy.get('[data-testid=navbar-user-desktop]').should('not.be.visible');
      cy.get('[data-testid=navbar-profile-desktop]').should('not.be.visible');
      cy.get('[data-testid=navbar-logout-desktop]').should('not.be.visible');
      cy.get('[data-testid=navbar-menu-desktop]').click();
      cy.get('[data-testid=navbar-user-desktop]').should('be.visible');
      cy.get('[data-testid=navbar-profile-desktop]').should('be.visible');
      cy.get('[data-testid=navbar-logout-desktop]').should('be.visible');
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

    it('should display the client-side rendered page', () => {
      cy.get('[data-testid=navbar-csr]').click();
      cy.url().should('eq', `${Cypress.config().baseUrl}/csr`);

      cy.get('[data-testid=navbar-csr]').isActive();
      cy.get('[data-testid=csr]').should('be.visible');
    });

    it('should display the server-side rendered page', () => {
      cy.get('[data-testid=navbar-ssr]').click();
      cy.url().should('eq', `${Cypress.config().baseUrl}/ssr`);

      cy.get('[data-testid=navbar-ssr]').isActive();
      cy.get('[data-testid=ssr]').should('be.visible');
      cy.get('[data-testid=ssr-json]').contains(EMAIL);
    });

    it('should display the external API page', () => {
      cy.get('[data-testid=navbar-external]').click();
      cy.url().should('eq', `${Cypress.config().baseUrl}/external`);

      cy.get('[data-testid=navbar-external]').isActive();
      cy.get('[data-testid=external]').should('be.visible');
    });

    it('should display the external API result', () => {
      cy.get('[data-testid=navbar-external]').click();
      cy.get('[data-testid=external-action]').click();
      cy.get('[data-testid=external-result]').should('be.visible');
    });

    it('should display the profile page', () => {
      cy.get('[data-testid=navbar-menu-desktop]').click();
      cy.get('[data-testid=navbar-profile-desktop]').click();
      cy.url().should('eq', `${Cypress.config().baseUrl}/profile`);

      cy.get('[data-testid=profile]').should('be.visible');
      cy.get('[data-testid=profile-email]').contains(EMAIL);
      cy.get('[data-testid=profile-json]').contains(EMAIL);
    });
  });

  context('mobile', () => {
    beforeEach(() => {
      cy.mobileViewport();
      cy.visit('/');
      cy.get('[data-testid=navbar-toggle]').click();
      cy.get('[data-testid=navbar-login-mobile]').click();
      login();
    });

    it('should expand the navigation bar menu', () => {
      cy.get('[data-testid=navbar-items]').should('not.be.visible');
      cy.get('[data-testid=navbar-menu-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-picture-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-user-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-profile-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-logout-mobile]').should('not.be.visible');
      cy.get('[data-testid=navbar-toggle]').click();
      cy.get('[data-testid=navbar-items]').should('be.visible');
      cy.get('[data-testid=navbar-menu-mobile]').should('be.visible');
      cy.get('[data-testid=navbar-picture-mobile]').should('be.visible');
      cy.get('[data-testid=navbar-user-mobile]').should('be.visible');
      cy.get('[data-testid=navbar-profile-mobile]').should('be.visible');
      cy.get('[data-testid=navbar-logout-mobile]').should('be.visible');
    });
  });
});
