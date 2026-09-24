import React, { memo } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { ListApiScreen } from './ListApiScreen';
import { FraudAlert, MobileApi } from '../services/MobileApi';

// Memoized row: only re-renders when its alert object identity changes.
const AlertRow = memo(function AlertRow({ alert }: { alert: FraudAlert }): React.JSX.Element {
  return (
    <View style={styles.row}>
      <Text style={styles.rowTitle}>{alert.title}</Text>
      <Text style={styles.meta}>{alert.severity.toUpperCase()} · {alert.status}</Text>
      <Text style={styles.date}>{new Date(alert.createdAt).toLocaleString()}</Text>
    </View>
  );
});

// Module-level stable references so FlatList props never change identity.
const renderAlert = (item: FraudAlert): React.ReactElement => <AlertRow alert={item} />;
const alertKey = (item: FraudAlert): string => item.id;

export default function FraudAlertsScreen(): React.JSX.Element {
  return (
    <ListApiScreen
      title="Fraud alerts"
      load={MobileApi.alerts}
      keyExtractor={alertKey}
      renderItem={renderAlert}
      emptyLabel="No fraud alerts."
    />
  );
}

const styles = StyleSheet.create({
  row: { paddingVertical: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#d1d5db' },
  rowTitle: { fontSize: 16, fontWeight: '600', color: '#111827' },
  meta: { color: '#374151', marginTop: 2 },
  date: { color: '#6b7280', fontSize: 12, marginTop: 2 },
});
