import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react-native';
import { Text } from 'react-native';
import { MobileApi } from '../services/MobileApi';
import { ListApiScreen } from './ListApiScreen';
import FraudAlertsScreen from './FraudAlertsScreen';
import NotificationsScreen from './NotificationsScreen';
import DocumentListScreen from './DocumentListScreen';

jest.mock('../services/MobileApi', () => ({
  MobileApi: {
    documents: jest.fn(),
    notifications: jest.fn(),
    alerts: jest.fn(),
  },
}));

const api = MobileApi as jest.Mocked<typeof MobileApi>;

beforeEach(() => {
  jest.clearAllMocks();
});

interface Row {
  id: string;
  label: string;
}

const renderRowLabel = (item: Row): React.ReactElement => <Text>{item.label}</Text>;
const rowKey = (item: Row): string => item.id;

describe('ListApiScreen virtualization', () => {
  it('renders server rows through the FlatList window', async () => {
    const rows = Array.from({ length: 30 }, (_, index) => ({ id: `row-${index}`, label: `Label ${index}` }));
    const load = jest.fn().mockResolvedValue(rows);
    const view = await render(
      <ListApiScreen title="Rows" load={load} keyExtractor={rowKey} renderItem={renderRowLabel} emptyLabel="No rows." />,
    );
    await waitFor(() => expect(view.getByText('Label 0')).toBeTruthy());
    expect(view.getByText('Label 11')).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('renders the empty label when the server returns no rows', async () => {
    const load = jest.fn().mockResolvedValue([]);
    const view = await render(
      <ListApiScreen title="Rows" load={load} keyExtractor={rowKey} renderItem={renderRowLabel} emptyLabel="No rows." />,
    );
    await waitFor(() => expect(view.getByText('No rows.')).toBeTruthy());
  });

  it('shows the server error and retries the load', async () => {
    const load = jest.fn()
      .mockRejectedValueOnce(new Error('backend unavailable'))
      .mockResolvedValueOnce([{ id: 'row-1', label: 'Recovered' }]);
    const view = await render(
      <ListApiScreen title="Rows" load={load} keyExtractor={rowKey} renderItem={renderRowLabel} emptyLabel="No rows." />,
    );
    await waitFor(() => expect(view.getByText('backend unavailable')).toBeTruthy());
    fireEvent.press(view.getByText('Retry'));
    await waitFor(() => expect(view.getByText('Recovered')).toBeTruthy());
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('uses the safe fallback when the load rejects a non-Error value', async () => {
    const load = jest.fn().mockRejectedValue('unexpected');
    const view = await render(
      <ListApiScreen title="Rows" load={load} keyExtractor={rowKey} renderItem={renderRowLabel} emptyLabel="No rows." />,
    );
    await waitFor(() => expect(view.getByText('Request failed')).toBeTruthy());
  });
});

describe('virtualized server list screens', () => {
  it('FraudAlertsScreen renders memoized alert rows', async () => {
    api.alerts.mockResolvedValue([
      { id: 'alert-1', title: 'Credential stuffing', severity: 'critical', status: 'open', createdAt: '2026-08-21T00:00:00Z' },
    ]);
    const view = await render(<FraudAlertsScreen />);
    await waitFor(() => expect(view.getByText('Credential stuffing')).toBeTruthy());
    expect(view.getByText(/CRITICAL · open/)).toBeTruthy();
  });

  it('NotificationsScreen distinguishes read and unread rows', async () => {
    api.notifications.mockResolvedValue([
      { id: 'n-1', title: 'Unread notice', body: 'Body one', createdAt: '2026-08-21T00:00:00Z' },
      { id: 'n-2', title: 'Read notice', body: 'Body two', readAt: '2026-08-21T01:00:00Z', createdAt: '2026-08-21T00:00:00Z' },
    ]);
    const view = await render(<NotificationsScreen />);
    await waitFor(() => expect(view.getByText(/● Unread notice/)).toBeTruthy());
    expect(view.getByText('Read notice')).toBeTruthy();
  });

  it('DocumentListScreen renders memoized document rows', async () => {
    api.documents.mockResolvedValue([
      { id: 'doc-1', name: 'passport.pdf', type: 'passport', status: 'verified', createdAt: '2026-08-21T00:00:00Z' },
    ]);
    const view = await render(<DocumentListScreen />);
    await waitFor(() => expect(view.getByText('passport.pdf')).toBeTruthy());
    expect(view.getByText(/passport · verified/)).toBeTruthy();
  });
});
