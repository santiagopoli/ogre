import { useEffect, useState } from 'react';
import { api } from '../api';
import type { KeysResponse } from '../api';

export function Keys() {
  const [keys, setKeys] = useState<KeysResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.keys().then(setKeys).catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
    );
  }

  if (!keys) return <div className="text-gray-500 text-sm">Loading...</div>;

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold">Public Keys</h2>
      <p className="text-sm text-gray-500">
        These are the public verification keys. Private keys never leave their respective holders.
      </p>

      <div className="space-y-4">
        <KeyCard label="Ogre Agent" pubkey={keys.ogre} color="text-green-400" />
        <KeyCard label="Reviewer Agent" pubkey={keys.reviewer} color="text-blue-400" />
        <KeyCard label="User" pubkey={keys.user} color="text-purple-400" />
      </div>
    </div>
  );
}

function KeyCard({ label, pubkey, color }: { label: string; pubkey: string | null; color: string }) {
  return (
    <div className="p-4 border border-gray-800 rounded bg-gray-900">
      <div className={`text-sm font-semibold ${color}`}>{label}</div>
      <div className="mt-2 font-mono text-xs text-gray-400 break-all">
        {pubkey || 'Not generated'}
      </div>
    </div>
  );
}
