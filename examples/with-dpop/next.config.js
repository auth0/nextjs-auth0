module.exports = {
  poweredByHeader: false,
  env: {
    // Make API_PORT available to client-side code
    NEXT_PUBLIC_API_PORT: process.env.API_PORT || '3001'
  }
};
