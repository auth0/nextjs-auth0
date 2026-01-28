'use client';

interface ProtectedDataProps {
  data: any;
  expiresAt?: number;
}

export function ProtectedData({ data, expiresAt }: ProtectedDataProps) {
  return (
    <div className="bg-green-50 border border-green-200 rounded-lg p-6">
      <div className="flex items-start gap-3">
        <svg className="h-6 w-6 text-green-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-green-900 mb-2">
            Protected Resource Access Granted
          </h3>
          <p className="text-sm text-green-700 mb-4">
            You have successfully completed MFA authentication. The data below is from a protected API.
          </p>
          <div className="bg-white rounded p-4">
            <pre className="text-sm overflow-x-auto">
              {JSON.stringify(data, null, 2)}
            </pre>
          </div>
          {expiresAt && (
            <p className="text-xs text-green-600 mt-3">
              Token expires: {new Date(expiresAt * 1000).toLocaleString()}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
