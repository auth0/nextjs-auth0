import {
  ConnectAccountError,
  ConnectAccountErrorCodes,
  ConnectedAccountsError,
  ConnectedAccountsErrorCodes,
  MyAccountApiError
} from "../../errors/index.js";

/**
 * Builds a ConnectAccountError response based on the provided Response object and error code.
 * @param res The Response object containing the error details.
 * @param errorCode The ConnectAccountErrorCodes enum value representing the type of error.
 * @returns
 */
export async function buildConnectAccountErrorResponse(
  res: Response,
  errorCode: ConnectAccountErrorCodes
): Promise<[ConnectAccountError, null]> {
  const actionVerb =
    errorCode === ConnectAccountErrorCodes.FAILED_TO_INITIATE
      ? "initiate"
      : "complete";

  try {
    const errorBody = await res.json();
    return [
      new ConnectAccountError({
        code: errorCode,
        message: `The request to ${actionVerb} the connect account flow failed with status ${res.status}.`,
        cause: new MyAccountApiError({
          type: errorBody.type,
          title: errorBody.title,
          detail: errorBody.detail,
          status: res.status,
          validationErrors: errorBody.validation_errors
        })
      }),
      null
    ];
  } catch (e) {
    return [
      new ConnectAccountError({
        code: errorCode,
        message: `The request to ${actionVerb} the connect account flow failed with status ${res.status}.`
      }),
      null
    ];
  }
}

export async function buildConnectedAccountsErrorResponse(
  res: Response,
  errorCode: ConnectedAccountsErrorCodes
): Promise<[ConnectedAccountsError, null]> {
  const actionVerb =
    errorCode === ConnectedAccountsErrorCodes.FAILED_TO_LIST
      ? "list the connected accounts"
      : "delete the connected account";

  try {
    const errorBody = await res.json();
    return [
      new ConnectedAccountsError({
        code: errorCode,
        message: `The request to ${actionVerb} failed with status ${res.status}.`,
        cause: new MyAccountApiError({
          type: errorBody.type,
          title: errorBody.title,
          detail: errorBody.detail,
          status: res.status,
          validationErrors: errorBody.validation_errors
        })
      }),
      null
    ];
  } catch (e) {
    return [
      new ConnectedAccountsError({
        code: errorCode,
        message: `The request to ${actionVerb} failed with status ${res.status}.`
      }),
      null
    ];
  }
}
