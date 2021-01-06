const EMAIL = Cypress.env('USER_EMAIL');
const PASSWORD = Cypress.env('USER_PASSWORD');

if (!EMAIL || !PASSWORD) {
  throw new Error('You must provide CYPRESS_USER_EMAIL and CYPRESS_USER_PASSWORD environment variables');
}

const loginToAuth0 = (): void => {
  cy.visit('/');
  cy.get('#login').click();
  cy.get('.auth0-lock-input-email input').focus().clear().type(EMAIL);
  cy.get('.auth0-lock-input-password input').focus().clear().type(PASSWORD);
  cy.get('.auth0-lock-submit').click();
};

describe('Smoke tests', () => {
  it('should do basic login and show user', () => {
    loginToAuth0();

    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.get('#profile').contains(EMAIL);
    cy.get('#logout').click();
    cy.get('#login').should('exist');
  });

  it('should protect a client-side rendered page', () => {
    loginToAuth0();

    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.visit('/profile');
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile`);
    cy.get('#profile').contains(EMAIL);
    cy.get('#logout').click();
  });

  it('should protect a server-side-rendered page', () => {
    loginToAuth0();

    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.visit('/profile-ssr');
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile-ssr`);
    cy.get('#profile').contains(EMAIL);
    cy.get('#logout').click();
  });
});
