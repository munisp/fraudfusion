import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react-native';
import { ApiScreen } from './ApiScreen';

const serverValue = { id: 'server-1', status: 'persisted' };

describe('ApiScreen interaction branches', () => {
  it('renders server data after a load with no action configured', async () => {
    const load = jest.fn().mockResolvedValue(serverValue);
    const view = await render(<ApiScreen title="No action" load={load} />);
    await waitFor(() => expect(view.getByText(/server-1/)).toBeTruthy());
    expect(view.queryByText('Retry')).toBeNull();
  });

  it('executes an action and replaces state with the returned server value', async () => {
    const load = jest.fn().mockResolvedValue({ id: 'before' });
    const action = jest.fn().mockResolvedValue(serverValue);
    const view = await render(<ApiScreen title="Action" load={load} actionLabel="Persist" action={action} />);
    await waitFor(() => expect(view.getByText(/before/)).toBeTruthy());
    fireEvent.press(view.getByText('Persist'));
    await waitFor(() => expect(action).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(view.getByText(/server-1/)).toBeTruthy());
  });

  it('renders an action failure and supports retrying the original load', async () => {
    const load = jest.fn().mockResolvedValue({ id: 'initial' });
    const action = jest.fn().mockRejectedValue(new Error('server rejected action'));
    const view = await render(<ApiScreen title="Action failure" load={load} actionLabel="Persist" action={action} />);
    await waitFor(() => expect(view.getByText(/initial/)).toBeTruthy());
    fireEvent.press(view.getByText('Persist'));
    await waitFor(() => expect(view.getByText('server rejected action')).toBeTruthy());
    fireEvent.press(view.getByText('Retry'));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
  });

  it('uses the safe fallback when an action throws a non-Error value', async () => {
    const load = jest.fn().mockResolvedValue({ id: 'initial' });
    const action = jest.fn().mockRejectedValue('unexpected');
    const view = await render(<ApiScreen title="Unknown failure" load={load} actionLabel="Persist" action={action} />);
    await waitFor(() => expect(view.getByText(/initial/)).toBeTruthy());
    fireEvent.press(view.getByText('Persist'));
    await waitFor(() => expect(view.getByText('Action failed')).toBeTruthy());
  });
});


describe('ApiScreen load fallback', () => {
  it('uses the safe fallback when the initial load rejects a non-Error value', async () => {
    const load = jest.fn().mockRejectedValue('unexpected');
    const view = await render(<ApiScreen title="Load fallback" load={load} />);
    await waitFor(() => expect(view.getByText('Request failed')).toBeTruthy());
  });
});
