import '@fontsource/ibm-plex-sans/latin-400.css';
import '@fontsource/ibm-plex-sans/latin-500.css';
import '@fontsource/ibm-plex-sans/latin-600.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import '@mantine/charts/styles.css';
import './index.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { theme } from './theme';
import { App } from './App';
import { StoreProvider } from './model/store';
import { SessionGate } from './lib/session';
import { ModeProvider } from './lib/mode';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications position="top-right" />
      <SessionGate>
        <ModeProvider>
          <StoreProvider>
            <App />
          </StoreProvider>
        </ModeProvider>
      </SessionGate>
    </MantineProvider>
  </StrictMode>,
);
