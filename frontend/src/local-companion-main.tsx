import React from 'react';
import { createRoot } from 'react-dom/client';
import { LocalCompanionView } from './LocalCompanionView.js';
import './styles.css';
import './local-companion.css';

// No authenticated IPC is implemented; never synthesize a connected status,
// poll the Go development API, or reuse the lab bearer token for local health.
const root = document.getElementById('root');
if (!root) throw new Error('Missing local companion root');
createRoot(root).render(
  <React.StrictMode>
    <LocalCompanionView snapshot={null} nowMs={Date.now()} />
  </React.StrictMode>,
);
