const EMAIL = Cypress.env('USER_EMAIL');
const PASSWORD = Cypress.env('USER_PASSWORD');

if (!EMAIL || !PASSWORD) {
  throw new Error('You must provide CYPRESS_USER_EMAIL and CYPRESS_USER_PASSWORD environment variables');
}

describe('smoke tests', () => {
  beforeEach(() => {
    cy.visit('/');
    cy.get('[data-testid=login]').click();
    cy.get('input[name=email], input[name=username]').focus().clear().type(EMAIL);
    cy.get('input[name=password]').focus().clear().type(PASSWORD);
    cy.get('button[name=submit], button[name=action]').click();
  });

  afterEach(() => {
    cy.get('[data-testid=logout]').click();
  });

  it('should do basic login and show user', () => {
    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.get('[data-testid=profile]').contains(EMAIL);
    cy.get('[data-testid=logout]').should('exist');
  });

  it('should protect a client-side rendered page', () => {
    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.visit('/profile');
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile`);
    cy.get('[data-testid=profile]').contains(EMAIL);
  });

  it('should protect a server-side-rendered page', () => {
    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.visit('/profile-ssr');
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile-ssr`);
    cy.get('[data-testid=profile]').contains(EMAIL);
  });
});
