import { useEffect, useState } from 'react';
import { api } from '../api';
import type { AuditEntry, ChainVerification } from '../api';

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.audit({ limit: '50' }).then(setEntries).catch((e) => setError(e.message));
    api.verifyChain().then(setChain).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Audit Log</h2>
        {chain && (
          <div className="flex items-center gap-2 text-sm">
            <span className={`w-2 h-2 rounded-full ${chain.valid ? 'bg-green-400' : 'bg-red-400'}`} />
            Chain: {chain.valid ? 'Valid' : 'BROKEN'}
            <span className="text-gray-500">({chain.entries_checked} entries)</span>
          </div>
        )}
      </div>

      {error && (
        <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
      )}

      <div className="border border-gray-800 rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              <th className="text-left px-4 py-2">#</th>
              <th className="text-left px-4 py-2">Time</th>
              <th className="text-left px-4 py-2">Action ID</th>
              <th className="text-left px-4 py-2">Level</th>
              <th className="text-left px-4 py-2">Decision</th>
              <th className="text-left px-4 py-2">Step</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.sequence} className="border-t border-gray-800 hover:bg-gray-900">
                <td className="px-4 py-2 text-gray-500">{e.sequence}</td>
                <td className="px-4 py-2 text-gray-400 text-xs">{new Date(e.timestamp).toLocaleString()}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.action_id.slice(0, 12)}</td>
                <td className="px-4 py-2">
                  {e.classification && (
                    <LevelBadge level={e.classification} />
                  )}
                </td>
                <td className="px-4 py-2">
                  <DecisionBadge decision={e.decision} />
                </td>
                <td className="px-4 py-2 text-gray-500 text-xs">{e.step_reached}</td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No audit entries</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    read: 'bg-blue-900 text-blue-300',
    write: 'bg-yellow-900 text-yellow-300',
    destructive: 'bg-red-900 text-red-300',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${colors[level] || 'bg-gray-800 text-gray-300'}`}>
      {level}
    </span>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  const isApproved = decision.includes('Approved') && !decision.includes('Pending');
  const isDenied = decision.includes('Denied');
  const isPending = decision.includes('Pending');

  let cls = 'bg-gray-800 text-gray-300';
  if (isApproved) cls = 'bg-green-900 text-green-300';
  if (isDenied) cls = 'bg-red-900 text-red-300';
  if (isPending) cls = 'bg-yellow-900 text-yellow-300';

  const label = isApproved ? 'Approved' : isDenied ? 'Denied' : isPending ? 'Pending' : 'Error';

  return <span className={`px-2 py-0.5 rounded text-xs ${cls}`}>{label}</span>;
}
