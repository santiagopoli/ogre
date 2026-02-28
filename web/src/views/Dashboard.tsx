import { useEffect, useState } from 'react';
import { api } from '../api';
import type { DashboardSummary } from '../api';

export function Dashboard() {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) return <ErrorBox message={error} />;
  if (!data) return <Loading />;

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold">Dashboard</h2>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Actions" value={data.total_actions} />
        <StatCard label="Pending Approvals" value={data.pending_actions} warn={data.pending_actions > 0} />
        <StatCard label="Connectors" value={data.connectors_count} />
        <StatCard label="Rules" value={data.rules_count} />
      </div>

      <div className="p-4 rounded border border-gray-800 bg-gray-900">
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${data.chain_valid ? 'bg-green-400' : 'bg-red-400'}`} />
          <span className="text-sm">
            Audit chain: {data.chain_valid ? 'Valid' : 'BROKEN'}
          </span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, warn }: { label: string; value: number; warn?: boolean }) {
  return (
    <div className="p-4 rounded border border-gray-800 bg-gray-900">
      <div className="text-xs text-gray-500 uppercase tracking-wider">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${warn ? 'text-yellow-400' : 'text-gray-100'}`}>
        {value}
      </div>
    </div>
  );
}

function Loading() {
  return <div className="text-gray-500 text-sm">Loading...</div>;
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="p-4 rounded border border-red-800 bg-red-950 text-red-300 text-sm">
      {message}
    </div>
  );
}
