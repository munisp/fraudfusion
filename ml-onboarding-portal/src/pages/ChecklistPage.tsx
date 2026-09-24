import React, { useCallback, useEffect, useState } from 'react';
import { ChecklistItem, onboardingApi } from '../api';
import { ErrorBanner } from '../components/ErrorBanner';

export default function ChecklistPage() {
  const [items, setItems] = useState<ChecklistItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingId, setPendingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await onboardingApi.getChecklist();
      setItems(data.items);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load the integration checklist.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (item: ChecklistItem) => {
    setPendingId(item.id);
    setError(null);
    try {
      const updated = await onboardingApi.updateChecklistItem(item.id, !item.done);
      setItems((current) => current?.map((it) => (it.id === updated.id ? updated : it)) ?? null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to update the checklist item.');
    } finally {
      setPendingId(null);
    }
  };

  return (
    <section>
      <h2>Integration checklist</h2>
      <p className="muted">Track the steps required before your tenant can go live.</p>
      {error && <ErrorBanner error={error} onRetry={load} />}
      {loading && <p className="muted">Loading checklist...</p>}
      {items && items.length === 0 && <p className="muted">No checklist items yet.</p>}
      {items && (
        <ul className="card checklist">
          {items.map((item) => (
            <li key={item.id}>
              <label>
                <input
                  type="checkbox"
                  checked={item.done}
                  disabled={pendingId === item.id}
                  onChange={() => void toggle(item)}
                />
                <span className={item.done ? 'done' : ''}>
                  {item.label}
                  {item.required && <em className="required">required</em>}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
