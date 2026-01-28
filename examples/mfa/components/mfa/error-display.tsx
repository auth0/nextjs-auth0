'use client';

interface ErrorDisplayProps {
  error: { error?: string; error_description?: string } | Error | string | { message: string; type?: 'success' | 'info' | 'error' };
  onDismiss?: () => void;
  onRetry?: () => void;
}

export function ErrorDisplay({ error, onDismiss, onRetry }: ErrorDisplayProps) {
  const getErrorMessage = () => {
    if (typeof error === 'string') return error;
    if (error instanceof Error) return error.message;
    if (typeof error === 'object' && 'message' in error) return error.message;
    if (typeof error === 'object' && 'error_description' in error) return (error as any).error_description;
    if (typeof error === 'object' && 'error' in error) return (error as any).error;
    return 'An error occurred';
  };

  const getErrorCode = () => {
    if (typeof error === 'object' && 'error' in error) {
      return (error as any).error;
    }
    return null;
  };

  const getType = (): 'success' | 'info' | 'error' => {
    if (typeof error === 'object' && 'type' in error) {
      return error.type as 'success' | 'info' | 'error';
    }
    return 'error';
  };

  const type = getType();
  const colors = {
    success: { bg: 'bg-green-50', border: 'border-green-200', icon: 'text-green-400', text: 'text-green-800', detail: 'text-green-700' },
    info: { bg: 'bg-blue-50', border: 'border-blue-200', icon: 'text-blue-400', text: 'text-blue-800', detail: 'text-blue-700' },
    error: { bg: 'bg-red-50', border: 'border-red-200', icon: 'text-red-400', text: 'text-red-800', detail: 'text-red-700' }
  }[type];
  
  const showDebug = process.env.NODE_ENV === 'development';

  return (
    <div className={`${colors.bg} border ${colors.border} rounded-lg p-4`}>
      <div className="flex items-start">
        <div className="flex-shrink-0">
          {type === 'success' ? (
            <svg className={`h-5 w-5 ${colors.icon}`} viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          ) : (
            <svg className={`h-5 w-5 ${colors.icon}`} viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          )}
        </div>
        <div className="ml-3 flex-1">
          <h3 className={`text-sm font-medium ${colors.text}`}>
            {type === 'success' ? 'Success' : type === 'info' ? 'Info' : 'Error'}
          </h3>
          <div className={`mt-2 text-sm ${colors.detail}`}>
            <p>{getErrorMessage()}</p>
            {getErrorCode() && (
              <p className={`mt-1 text-xs font-mono ${colors.detail}`}>
                Code: {getErrorCode()}
              </p>
            )}
          </div>
          {showDebug && typeof error === 'object' && type === 'error' && (
            <details className="mt-3">
              <summary className="text-xs font-mono text-red-600 cursor-pointer">Debug Info</summary>
              <pre className="mt-2 p-2 bg-red-100 rounded overflow-x-auto text-xs">
                {JSON.stringify(error, null, 2)}
              </pre>
            </details>
          )}
          {(onRetry || onDismiss) && (
            <div className="mt-4 flex gap-2">
              {onRetry && (
                <button
                  onClick={onRetry}
                  className="px-3 py-1 bg-red-600 text-white text-sm rounded hover:bg-red-700"
                >
                  Retry
                </button>
              )}
              {onDismiss && (
                <button
                  onClick={onDismiss}
                  className="px-3 py-1 bg-white border border-red-300 text-red-700 text-sm rounded hover:bg-red-50"
                >
                  Dismiss
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
