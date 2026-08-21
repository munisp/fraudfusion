import React from 'react';
import { createRoot } from 'react-dom/client';
import JourneyDashboard from './pages/JourneyDashboard';
import './styles.css';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('The application root element is missing.');
}

createRoot(rootElement).render(
  <React.StrictMode>
    <JourneyDashboard />
  </React.StrictMode>,
);
