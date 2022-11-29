const useAuth0 = Cypress.env('USE_AUTH0');
const EMAIL = useAuth0 ? Cypress.env('USER_EMAIL') : 'test';
const PASSWORD = useAuth0 ? Cypress.env('USER_PASSWORD') : 'test';

if (!EMAIL || !PASSWORD) {
  throw new Error('You must provide CYPRESS_USER_EMAIL and CYPRESS_USER_PASSWORD environment variables');
}

const loginToAuth0 = () => {
  cy.get('input[name=email], input[name=username]').focus().clear().type(EMAIL);
  cy.get('input[name=password]').focus().clear().type(PASSWORD);
  cy.get('button[name=submit], button[name=action]').click();
};

const loginToNodeOidc = () => {
  cy.get('input[name=login]').focus().clear().type(EMAIL);
  cy.get('input[name=password]').focus().clear().type(PASSWORD);
  cy.get('button.login').click();
  cy.get('button.login').click();
};

const login = useAuth0 ? loginToAuth0 : loginToNodeOidc;

describe('smoke tests', () => {
  it('should do basic login and show user', () => {
    cy.visit('/');
    cy.window().its('__DEV_PAGES_MANIFEST'); // wait for pages to load so FF doesn't fail
    cy.get('[data-testid=login]').click();
    login();
    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.get('[data-testid=profile]').contains(EMAIL);
    cy.get('[data-testid=logout]').should('exist');
  });

  it('should protect a client-side rendered page', () => {
    cy.visit('/profile');
    login();
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile`);
    cy.get('[data-testid=profile]').contains(EMAIL);
  });

  it('should protect a server-side rendered page', () => {
    cy.visit('/profile-ssr');
    login();

    cy.url().should('eq', `${Cypress.config().baseUrl}/profile-ssr`);
    cy.get('[data-testid=profile]').contains(EMAIL);
  });

  it('should logout and return to the index page', () => {
    cy.visit('/profile');
    login();
    cy.url().should('eq', `${Cypress.config().baseUrl}/profile`);
    cy.window().its('__DEV_PAGES_MANIFEST'); // wait for pages to load so FF doesn't fail
    cy.get('[data-testid=logout]').click();
    if (!useAuth0) {
      cy.get('[name=logout]').click();
    }
    cy.url().should('eq', `${Cypress.config().baseUrl}/`);
    cy.get('[data-testid=login]').should('exist');
  });
});
