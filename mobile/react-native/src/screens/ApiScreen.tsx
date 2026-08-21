import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Button, ScrollView, StyleSheet, Text, View } from 'react-native';

interface ApiScreenProps<T> {
  title: string;
  load: () => Promise<T>;
  actionLabel?: string;
  action?: () => Promise<T>;
}

export function ApiScreen<T>({ title, load, actionLabel, action }: ApiScreenProps<T>): React.JSX.Element {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setValue(await load());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  }, [load]);

  useEffect(() => { void refresh(); }, [refresh]);

  const executeAction = useCallback(async (operation: () => Promise<T>) => {
    setLoading(true);
    setError(null);
    try {
      setValue(await operation());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Action failed');
    } finally {
      setLoading(false);
    }
  }, []);

  return <ScrollView contentContainerStyle={styles.container}>
    <Text accessibilityRole="header" style={styles.title}>{title}</Text>
    {loading && <ActivityIndicator accessibilityLabel="Loading server data" />}
    {error && <View><Text style={styles.error}>{error}</Text><Button title="Retry" onPress={() => void refresh()} /></View>}
    {value !== null && <Text selectable style={styles.data}>{JSON.stringify(value, null, 2)}</Text>}
    {action && actionLabel && <Button title={actionLabel} onPress={() => void executeAction(action)} disabled={loading} />}
  </ScrollView>;
}

const styles = StyleSheet.create({ container: { flexGrow: 1, padding: 20, gap: 16 }, title: { fontSize: 24, fontWeight: '700' }, error: { color: '#b91c1c' }, data: { fontFamily: 'monospace', color: '#102a43' } });
