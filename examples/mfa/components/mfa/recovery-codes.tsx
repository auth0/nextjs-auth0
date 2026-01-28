'use client';

import { useState } from 'react';
import { Download, Copy } from 'lucide-react';

interface RecoveryCodesProps {
  codes: string[];
}

export function RecoveryCodes({ codes }: RecoveryCodesProps) {
  const [downloaded, setDownloaded] = useState(false);

  const handleDownload = () => {
    const text = `Auth0 MFA Recovery Codes
Generated: ${new Date().toISOString()}

IMPORTANT: Store these codes securely. Each code can only be used once.

${codes.map((code, i) => `${i + 1}. ${code}`).join('\n')}
`;

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mfa-recovery-codes-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);

    setDownloaded(true);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(codes.join('\n'));

  };

  return (
    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
      <h3 className="font-semibold text-yellow-900 mb-2">
        Recovery Codes
      </h3>
      <p className="text-sm text-yellow-800 mb-4">
        Save these codes in a secure location. You can use them to access your account if you lose your authenticator device.
      </p>
      <div className="bg-white rounded p-4 mb-4 font-mono text-sm space-y-1">
        {codes.map((code, i) => (
          <div key={i}>{code}</div>
        ))}
      </div>
      <div className="flex gap-2">
        <button
          onClick={handleDownload}
          className="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700"
        >
          {downloaded ? '✓ Downloaded' : 'Download Codes'}
        </button>
        <button
          onClick={handleCopy}
          className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
        >
          Copy to Clipboard
        </button>
      </div>
    </div>
  );
}
