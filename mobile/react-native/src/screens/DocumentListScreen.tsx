import React, { memo } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { ListApiScreen } from './ListApiScreen';
import { DocumentRecord, MobileApi } from '../services/MobileApi';

// Memoized row: only re-renders when its document object identity changes.
const DocumentRow = memo(function DocumentRow({ document }: { document: DocumentRecord }): React.JSX.Element {
  return (
    <View style={styles.row}>
      <Text style={styles.rowTitle}>{document.name}</Text>
      <Text style={styles.meta}>{document.type} · {document.status}</Text>
      <Text style={styles.date}>{new Date(document.createdAt).toLocaleString()}</Text>
    </View>
  );
});

// Module-level stable references so FlatList props never change identity.
const renderDocument = (item: DocumentRecord): React.ReactElement => <DocumentRow document={item} />;
const documentKey = (item: DocumentRecord): string => item.id;

export default function DocumentListScreen(): React.JSX.Element {
  return (
    <ListApiScreen
      title="Documents"
      load={MobileApi.documents}
      keyExtractor={documentKey}
      renderItem={renderDocument}
      emptyLabel="No documents yet."
    />
  );
}

const styles = StyleSheet.create({
  row: { paddingVertical: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#d1d5db' },
  rowTitle: { fontSize: 16, fontWeight: '600', color: '#111827' },
  meta: { color: '#374151', marginTop: 2 },
  date: { color: '#6b7280', fontSize: 12, marginTop: 2 },
});
