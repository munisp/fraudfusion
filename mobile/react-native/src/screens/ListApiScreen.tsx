import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Button, FlatList, StyleSheet, Text, View } from 'react-native';

/**
 * Generic server-backed list screen with real virtualization (M4 fix).
 * Replaces the "stringify the whole payload into one <Text> in a ScrollView"
 * pattern with a FlatList: windowed rendering, batching, and clipped-subview
 * removal keep scroll at 60fps on large payloads.
 */
interface ListApiScreenProps<T> {
  title: string;
  load: () => Promise<T[]>;
  keyExtractor: (item: T) => string;
  renderItem: (item: T) => React.ReactElement;
  emptyLabel: string;
}

export function ListApiScreen<T>({ title, load, keyExtractor, renderItem, emptyLabel }: ListApiScreenProps<T>): React.JSX.Element {
  const [items, setItems] = useState<T[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await load());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  }, [load]);

  useEffect(() => { void refresh(); }, [refresh]);

  const renderRow = useCallback(({ item }: { item: T }) => renderItem(item), [renderItem]);
  const renderEmpty = useCallback(() => <Text style={styles.empty}>{emptyLabel}</Text>, [emptyLabel]);

  return (
    <View style={styles.container}>
      <Text accessibilityRole="header" style={styles.title}>{title}</Text>
      {loading && <ActivityIndicator accessibilityLabel="Loading server data" />}
      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.error}>{error}</Text>
          <Button title="Retry" onPress={() => void refresh()} />
        </View>
      )}
      {items !== null && (
        <FlatList
          data={items}
          renderItem={renderRow}
          keyExtractor={keyExtractor}
          ListEmptyComponent={renderEmpty}
          initialNumToRender={12}
          maxToRenderPerBatch={12}
          windowSize={7}
          updateCellsBatchingPeriod={30}
          removeClippedSubviews
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, gap: 16 },
  title: { fontSize: 24, fontWeight: '700' },
  errorBox: { gap: 8 },
  error: { color: '#b91c1c' },
  empty: { color: '#6b7280', paddingVertical: 12 },
});
