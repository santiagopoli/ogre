import { useEffect, useState } from 'react';
import { api } from '../api';
import type { PendingActionResponse } from '../api';

export function PendingApprovals() {
  const [actions, setActions] = useState<PendingActionResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () => api.pendingActions().then(setActions).catch((e: Error) => setError(e.message));
  useEffect(() => { load(); }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Pending Approvals</h2>
        <button
          onClick={load}
          className="px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 border border-gray-700 hover:border-gray-600 rounded"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
      )}

      <div className="border border-gray-800 rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              <th className="text-left px-4 py-2">Action ID</th>
              <th className="text-left px-4 py-2">Agent</th>
              <th className="text-left px-4 py-2">Classification</th>
              <th className="text-left px-4 py-2">Reason</th>
              <th className="text-left px-4 py-2">Created</th>
              <th className="text-left px-4 py-2">Expires</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((a) => (
              <tr key={a.action_id} className="border-t border-gray-800 hover:bg-gray-900">
                <td className="px-4 py-2 font-mono text-xs text-gray-500">{a.action_id.slice(0, 12)}</td>
                <td className="px-4 py-2 font-mono text-xs">{a.agent_id}</td>
                <td className="px-4 py-2">
                  <ClassificationBadge level={a.classification} />
                </td>
                <td className="px-4 py-2 text-gray-300">{a.reason}</td>
                <td className="px-4 py-2 text-gray-400 text-xs">{new Date(a.created_at).toLocaleString()}</td>
                <td className="px-4 py-2 text-gray-400 text-xs">{new Date(a.expires_at).toLocaleString()}</td>
              </tr>
            ))}
            {actions.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No pending approvals</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ClassificationBadge({ level }: { level: string }) {
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
