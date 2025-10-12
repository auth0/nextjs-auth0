'use server';

import { auth0 } from '../../lib/auth0';

export async function testDpopServerAction(formData) {
  console.info('[ServerAction] Executing DPoP server action');
  
  try {
    // Get session in server action context
    const session = await auth0.getSession();
    
    if (!session) {
      console.info('[ServerAction] User not authenticated');
      return { 
        success: false, 
        error: { 
          error: 'Not authenticated',
          message: 'User session not found'
        } 
      };
    }

    console.info('[ServerAction] User authenticated, making DPoP API call');
    
    // Extract user message from form data
    const userMessage = formData.get('testMessage');
    
    // Use the same pattern as other examples for DPoP requests
    const relativePath = '/api/shows';
    
    const configuredOptions = {
      audience: 'https://dev-10whndm3tf8jetu5.us.auth0.com/api/v2/',
      scope: 'openid profile email offline_access',
      refresh: true
    };

    // Create fetcher with baseUrl configuration
    const fetcher = await auth0.createFetcher(undefined, {
      baseUrl: 'http://localhost:3001',
      getAccessToken: async function(getAccessTokenOptions) {
        console.info('[ServerAction] Custom getAccessToken called');
        console.info(JSON.stringify(getAccessTokenOptions));
        const at = await auth0.getAccessToken(getAccessTokenOptions);
        return at.token;
      }
    });

    const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);
    
    console.info('[ServerAction] Response received:', response.status, response.statusText);

    if (response.ok) {
      const dpopApiResponse = await response.json();
      console.info('[ServerAction] Successful DPoP response:', dpopApiResponse);
      
      // Add server action specific data
      const result = {
        ...dpopApiResponse,
        serverActionExecuted: true,
        executedAt: new Date().toISOString(),
        userMessage: userMessage || null
      };
      
      return { success: true, data: result };
    } else {
      const errorText = await response.text();
      const dpopError = {
        error: 'API request failed',
        status: response.status,
        statusText: response.statusText,
        body: errorText
      };
      console.info('[ServerAction] Error response:', dpopError);
      
      return { success: false, error: dpopError };
    }
    
  } catch (error) {
    console.error('[ServerAction] Error in DPoP request:', {
      errorName: error.name,
      errorMessage: error.message,
      errorStack: error.stack?.split('\n').slice(0, 5).join('\n')
    });
    
    const dpopError = {
      error: error.message,
      errorType: error.name,
      timestamp: new Date().toISOString()
    };
    
    return { success: false, error: dpopError };
  }
}