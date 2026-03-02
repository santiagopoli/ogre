import { useEffect, useState } from 'react';
import { api } from '../api';
import type { AgentResponse } from '../api';

export function Agents() {
  const [agents, setAgents] = useState<AgentResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  const load = () => api.agents().then(setAgents).catch((e: Error) => setError(e.message));
  useEffect(() => { load(); }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Agents</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-3 py-1.5 text-sm bg-green-600 hover:bg-green-500 rounded"
        >
          {showForm ? 'Cancel' : 'Register Agent'}
        </button>
      </div>

      {showForm && <RegisterForm onCreated={() => { setShowForm(false); load(); }} />}

      {error && (
        <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
      )}

      <div className="border border-gray-800 rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              <th className="text-left px-4 py-2">Agent ID</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.agent_id} className="border-t border-gray-800 hover:bg-gray-900">
                <td className="px-4 py-2 font-mono text-sm">{a.agent_id}</td>
              </tr>
            ))}
            {agents.length === 0 && (
              <tr><td className="px-4 py-8 text-center text-gray-500">No agents registered</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RegisterForm({ onCreated }: { onCreated: () => void }) {
  const [agentId, setAgentId] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!agentId.trim()) {
      setError('Agent ID is required');
      return;
    }
    try {
      await api.registerAgent(agentId.trim());
      onCreated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to register agent');
    }
  };

  return (
    <div className="p-4 border border-gray-800 rounded bg-gray-900 space-y-3">
      {error && <div className="text-red-400 text-sm">{error}</div>}
      <input
        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm"
        placeholder="Agent ID"
        value={agentId}
        onChange={(e) => setAgentId(e.target.value)}
      />
      <button
        onClick={submit}
        className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded text-sm"
      >
        Register
      </button>
    </div>
  );
}
