const navbarActiveClass = 'navbar-item-active';

Cypress.Commands.add(
  'isActive',
  {
    prevSubject: true
  },
  selector => {
    cy.get(selector).should('have.class', navbarActiveClass);

    const selectedItems = cy.get('[data-testid=navbar-items]').find('[data-testid|=navbar]');
    if (selectedItems.length > 1) selectedItems.not(selector).should('not.have.class', navbarActiveClass);
  }
);

Cypress.Commands.add('mobileViewport', () => cy.viewport(500, 1000));
