import { useEffect, useState } from 'react';
import { api } from '../api';
import type { RuleResponse } from '../api';

export function Rules() {
  const [rules, setRules] = useState<RuleResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  const load = () => api.rules().then(setRules).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Rules</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-3 py-1.5 text-sm bg-green-600 hover:bg-green-500 rounded"
        >
          {showForm ? 'Cancel' : 'Add Rule'}
        </button>
      </div>

      {showForm && <RuleForm onCreated={() => { setShowForm(false); load(); }} />}

      {error && (
        <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
      )}

      <div className="border border-gray-800 rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              <th className="text-left px-4 py-2">ID</th>
              <th className="text-left px-4 py-2">Description</th>
              <th className="text-left px-4 py-2">Effect</th>
              <th className="text-left px-4 py-2">Priority</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-900">
                <td className="px-4 py-2 font-mono text-xs text-gray-500">{r.id.slice(0, 12)}</td>
                <td className="px-4 py-2">{r.description}</td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    r.effect === 'allow' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'
                  }`}>
                    {r.effect}
                  </span>
                </td>
                <td className="px-4 py-2 text-gray-400">{r.priority}</td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-gray-500">No rules</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleForm({ onCreated }: { onCreated: () => void }) {
  const [desc, setDesc] = useState('');
  const [effect, setEffect] = useState<'allow' | 'deny'>('allow');
  const [priority, setPriority] = useState(0);
  const [condJson, setCondJson] = useState('{"op": "always"}');
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    try {
      const condition = JSON.parse(condJson);
      await api.createRule({ description: desc, condition, effect, priority });
      onCreated();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div className="p-4 border border-gray-800 rounded bg-gray-900 space-y-3">
      {error && <div className="text-red-400 text-sm">{error}</div>}
      <input
        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm"
        placeholder="Description"
        value={desc}
        onChange={(e) => setDesc(e.target.value)}
      />
      <div className="flex gap-3">
        <select
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm"
          value={effect}
          onChange={(e) => setEffect(e.target.value as 'allow' | 'deny')}
        >
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <input
          className="w-24 px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm"
          type="number"
          placeholder="Priority"
          value={priority}
          onChange={(e) => setPriority(Number(e.target.value))}
        />
      </div>
      <textarea
        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm font-mono h-24"
        placeholder='Condition JSON, e.g. {"op": "always"}'
        value={condJson}
        onChange={(e) => setCondJson(e.target.value)}
      />
      <button
        onClick={submit}
        className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded text-sm"
      >
        Create Rule
      </button>
    </div>
  );
}
