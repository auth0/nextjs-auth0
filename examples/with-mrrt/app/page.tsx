import { MouseEvent as ReactMouseEvent } from "react";

import { auth0 } from "@/lib/auth0";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator
} from "@/components/ui/breadcrumb";
import { Separator } from "@/components/ui/separator";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger
} from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";

export default function Page() {
  /**
   * Get an access token for the default audience configured in the Auth0Client.
   * @param e - React mouse event
   */
  async function getToken(e: ReactMouseEvent<HTMLButtonElement, MouseEvent>) {
    "use server";

    const token = await auth0.getAccessToken();

    // Logging the token on the server-side console to allow you to inspect it.
    console.log(token);
  }

  /**
   * Get an access token for audience 'test-1'.
   * @param e - React mouse event
   */
  async function getTokenForAudience1(
    e: ReactMouseEvent<HTMLButtonElement, MouseEvent>
  ) {
    "use server";

    const token = await auth0.getAccessToken({ audience: "{YOUR_API_IDENTIFIER_HERE}" });

    // Logging the token on the server-side console to allow you to inspect it.
    console.log(token);
  }

  /**
   * Get an access token for audience 'test-2'.
   * @param e - React mouse event
   */
  async function getTokenForAudience2(
    e: ReactMouseEvent<HTMLButtonElement, MouseEvent>
  ) {
    "use server";

    const token = await auth0.getAccessToken({ audience: "{YOUR_SECOND_API_IDENTIFIER_HERE}" });

    // Logging the token on the server-side console to allow you to inspect it.
    console.log(token);
  }

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2">
          <div className="flex items-center gap-2 px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 h-4" />
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden md:block">
                  <BreadcrumbLink href="#">
                    Building Your Application
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Data Fetching</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </header>
        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
          <div className="grid auto-rows-min gap-4 md:grid-cols-3">
            <div className="aspect-video rounded-xl bg-muted/50 p-4">
              <p className="mb-3 text-lg text-gray-500 md:text-xl dark:text-gray-400">
                What is MRRT?
              </p>
              <p className="mb-3 text-gray-500 dark:text-gray-400">
                Multi Resource Refresh Token (MRRT) is a feature of Auth0 that
                enables you to use a single refresh token to obtain access
                tokens for multiple audiences. It is recommended to ensure you
                understand the functionality and requirements of MRRT before
                implementing it in your application. More information can be
                found on{" "}
                <a
                  href="https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token"
                  className="font-medium text-blue-600 dark:text-blue-500 hover:underline"
                >
                  the Auth0 documentation about MRRT
                </a>
                .
              </p>
              <p className="mb-3 text-gray-500 dark:text-gray-400">
                When MRRT has been configured, the SDK can be used to obtain
                tokens for different audiences as long as those audiences are
                part of the Refresh Token Policies.
              </p>

              <div
                className="flex items-center p-4 mb-4 text-sm text-red-800 rounded-lg bg-red-50 dark:bg-gray-800 dark:text-red-400"
                role="alert"
              >
                <svg
                  className="shrink-0 inline w-4 h-4 me-3"
                  aria-hidden="true"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM9.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3ZM12 15H8a1 1 0 0 1 0-2h1v-3H8a1 1 0 0 1 0-2h2a1 1 0 0 1 1 1v4h1a1 1 0 0 1 0 2Z" />
                </svg>
                <span className="sr-only">Info</span>
                <div>
                  When requesting an Access Token for an audience outside of the
                  Refresh Token Policies, Auth0 will ignore the audience and
                  instead return an Access Token for the initial Audience when
                  configuring the Auth0Client.
                </div>
              </div>
            </div>
            <div className="aspect-video rounded-xl bg-muted/50 p-4">
              <p className="mb-3 text-lg text-gray-500 md:text-xl dark:text-gray-400">
                MRRT in action.
              </p>

              <p className="mb-3 text-gray-500 dark:text-gray-400">
                Click any of the buttons below to request a token for one of the
                audiences, where the first button does not explicily pass an
                audience to the SDK's `getAccessToken`, and instead uses the
                default audience configured in the Auth0Client.
              </p>

              <button
                type="button"
                className="text-white bg-gradient-to-br from-purple-600 to-blue-500 hover:bg-gradient-to-bl focus:ring-4 focus:outline-none focus:ring-blue-300 dark:focus:ring-blue-800 font-medium rounded-lg text-sm px-5 py-2.5 text-center me-2 mb-2"
                onClick={getToken}
              >
                Get Token
              </button>

              <button
                type="button"
                className="text-white bg-gradient-to-br from-purple-600 to-blue-500 hover:bg-gradient-to-bl focus:ring-4 focus:outline-none focus:ring-blue-300 dark:focus:ring-blue-800 font-medium rounded-lg text-sm px-5 py-2.5 text-center me-2 mb-2"
                onClick={getTokenForAudience1}
              >
                Get Token (Audience 1)
              </button>

              <button
                type="button"
                className="text-white bg-gradient-to-br from-purple-600 to-blue-500 hover:bg-gradient-to-bl focus:ring-4 focus:outline-none focus:ring-blue-300 dark:focus:ring-blue-800 font-medium rounded-lg text-sm px-5 py-2.5 text-center me-2 mb-2"
                onClick={getTokenForAudience2}
              >
                Get Token (Audience 2)
              </button>
            </div>
            <div className="aspect-video rounded-xl bg-muted/50 p-4">
              <p className="mb-3 text-lg text-gray-500 md:text-xl dark:text-gray-400">
                Example Configuration
              </p>

              <p className="mb-3 text-gray-500 dark:text-gray-400">
                Ensure to create and configure the <code>.env</code> values
                based on the provided <code>.env.example</code> file.
              </p>
              <p className="mb-3 text-gray-500 dark:text-gray-400">
                Additionally, for using MRRT, also ensure to:
              </p>
              <ul className="ml-3 max-w-md space-y-1 text-gray-500 list-disc list-inside dark:text-gray-400">
                <li>
                  Specificy a default audience by passing the correct{" "}
                  <code>authorizationParams.audience</code> when instantiating{" "}
                  <code>Auth0Client</code> in <code>lib/auth0.ts</code>
                </li>
                <li>
                  Update the different audiences configured in{" "}
                  <code>app/page.tsx</code> when calling{" "}
                  <code>auth0.getAccessToken()</code>
                </li>
              </ul>
            </div>
          </div>
          <div className="min-h-[100vh] flex-1 rounded-xl bg-muted/50 md:min-h-min" />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
