import { createTheme, type MantineColorsTuple } from '@mantine/core';

// Harbor: the working accent. Amber: brand mark and "pending" state.
const harbor: MantineColorsTuple = ['#e8f6fa', '#d3eaf1', '#a6d3e2', '#76bbd2', '#4fa7c4', '#3699ba', '#1f7f9e', '#156f8b', '#0b5f78', '#004e64'];
const amber: MantineColorsTuple = ['#fff7e0', '#ffeecb', '#fcdb9a', '#f9c764', '#f7b638', '#f5ab1b', '#e0a526', '#c78f12', '#b17e05', '#9a6c00'];
// Neutrals with a slight blue bias toward the accent.
const gray: MantineColorsTuple = ['#f5f7f9', '#eceff3', '#dfe4ea', '#ccd4dc', '#b1bcc7', '#94a1ae', '#75828f', '#5a6572', '#424b55', '#2b323a'];
const dark: MantineColorsTuple = ['#c9d1d9', '#a9b3be', '#8793a0', '#5f6b78', '#3a444f', '#2b343e', '#212932', '#1a2129', '#141a20', '#0f1419'];

export const theme = createTheme({
  primaryColor: 'harbor',
  primaryShade: { light: 7, dark: 5 },
  colors: { harbor, amber, gray, dark },
  fontFamily: '"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif',
  fontFamilyMonospace: '"IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace',
  headings: { fontFamily: '"IBM Plex Sans", system-ui, sans-serif', fontWeight: '600' },
  defaultRadius: 'md',
  cursorType: 'pointer',
  components: {
    Card: { defaultProps: { withBorder: true, radius: 'md', padding: 'lg' } },
    Paper: { defaultProps: { radius: 'md' } },
    Badge: { defaultProps: { variant: 'light', radius: 'sm' } },
    Table: { defaultProps: { verticalSpacing: 'sm', horizontalSpacing: 'md' } },
    Drawer: { defaultProps: { position: 'right', size: 'lg', padding: 'lg' } },
    Modal: { defaultProps: { centered: true, padding: 'lg' } },
    Tooltip: { defaultProps: { withArrow: true, openDelay: 300 } },
  },
});
