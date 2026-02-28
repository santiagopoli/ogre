import { useState } from 'react';
import { Dashboard } from './views/Dashboard';
import { Rules } from './views/Rules';
import { AuditLog } from './views/AuditLog';
import { Connectors } from './views/Connectors';
import { Keys } from './views/Keys';

type View = 'dashboard' | 'rules' | 'audit' | 'connectors' | 'keys';

const NAV_ITEMS: { id: View; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'rules', label: 'Rules' },
  { id: 'audit', label: 'Audit Log' },
  { id: 'connectors', label: 'Connectors' },
  { id: 'keys', label: 'Keys' },
];

export default function App() {
  const [view, setView] = useState<View>('dashboard');

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <h1 className="text-xl font-bold tracking-tight">
            <span className="text-green-400">OGRE</span>
            <span className="text-gray-500 ml-2 text-sm font-normal">
              Operational Governance for Resource Enforcement
            </span>
          </h1>
        </div>
      </header>

      <div className="max-w-7xl mx-auto flex">
        <nav className="w-48 border-r border-gray-800 min-h-[calc(100vh-65px)] p-4 space-y-1">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setView(item.id)}
              className={`w-full text-left px-3 py-2 rounded text-sm ${
                view === item.id
                  ? 'bg-gray-800 text-green-400'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <main className="flex-1 p-6">
          {view === 'dashboard' && <Dashboard />}
          {view === 'rules' && <Rules />}
          {view === 'audit' && <AuditLog />}
          {view === 'connectors' && <Connectors />}
          {view === 'keys' && <Keys />}
        </main>
      </div>
    </div>
  );
}
