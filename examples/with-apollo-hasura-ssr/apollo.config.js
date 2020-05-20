module.exports = {
  client: {
    service: {
      name: 'analytics-app',
      url: 'https://api.example.test/v1/graphql',
      headers: {
        'x-hasura-admin-secret': 'A3F96299E29D4DD59209D2944828AD6D'
      }
    },
  }
}
