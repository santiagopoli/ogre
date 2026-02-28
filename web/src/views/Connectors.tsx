import { useEffect, useState } from 'react';
import { api } from '../api';
import type { ConnectorResponse, CapabilityResponse } from '../api';

export function Connectors() {
  const [connectors, setConnectors] = useState<ConnectorResponse[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.connectors().then(setConnectors).catch((e) => setError(e.message));
  }, []);

  const selectConnector = async (id: string) => {
    setSelected(id);
    try {
      const caps = await api.capabilities(id);
      setCapabilities(caps);
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold">Connectors</h2>

      {error && (
        <div className="p-3 rounded border border-red-800 bg-red-950 text-red-300 text-sm">{error}</div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {connectors.map((c) => (
          <button
            key={c.id}
            onClick={() => selectConnector(c.id)}
            className={`p-4 rounded border text-left ${
              selected === c.id
                ? 'border-green-600 bg-gray-900'
                : 'border-gray-800 bg-gray-900 hover:border-gray-600'
            }`}
          >
            <div className="font-semibold">{c.name}</div>
            <div className="text-xs text-gray-500 font-mono">{c.id}</div>
          </button>
        ))}
        {connectors.length === 0 && (
          <div className="text-gray-500 text-sm">No connectors registered</div>
        )}
      </div>

      {selected && capabilities.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-gray-400">
            Capabilities for {selected}
          </h3>
          <div className="border border-gray-800 rounded overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-900 text-gray-400">
                <tr>
                  <th className="text-left px-4 py-2">ID</th>
                  <th className="text-left px-4 py-2">Name</th>
                  <th className="text-left px-4 py-2">Description</th>
                  <th className="text-left px-4 py-2">Level</th>
                </tr>
              </thead>
              <tbody>
                {capabilities.map((cap) => (
                  <tr key={cap.id} className="border-t border-gray-800">
                    <td className="px-4 py-2 font-mono text-xs">{cap.id}</td>
                    <td className="px-4 py-2">{cap.name}</td>
                    <td className="px-4 py-2 text-gray-400">{cap.description}</td>
                    <td className="px-4 py-2">
                      <span className={`px-2 py-0.5 rounded text-xs ${levelColor(cap.level)}`}>
                        {cap.level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function levelColor(level: string): string {
  switch (level) {
    case 'read': return 'bg-blue-900 text-blue-300';
    case 'write': return 'bg-yellow-900 text-yellow-300';
    case 'destructive': return 'bg-red-900 text-red-300';
    default: return 'bg-gray-800 text-gray-300';
  }
}
