module.exports = {
  poweredByHeader: false,
  experimental: {
    appDir: true
  },
  env: {
    // Set the baseUrl for the SDK to the Vercel "Automatic Branch URL" for Preview deploys. Use `${process.env.VERCEL_URL}` if you
    // would rather use the 'Automatic Deployment URL' (see: https://vercel.com/changelog/urls-are-becoming-consistent)
    //
    // For production deploys from the main branch or custom domains which are assigned to a specific branch (see https://vercel.com/docs/custom-domains#assigning-a-domain-to-a-git-branch)
    // you can assign the `AUTH0_BASE_URL` in the 'Environment Variables' section of your project's settings page which will override this.
    AUTH0_BASE_URL: `${process.env.VERCEL_GIT_REPO_SLUG}-git-${process.env.VERCEL_GIT_COMMIT_REF}-${process.env.VERCEL_GIT_REPO_OWNER}.vercel.app`
  }
};
