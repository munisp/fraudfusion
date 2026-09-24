import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Button, ScrollView, StyleSheet, Text } from 'react-native';
import { DocumentRecord, MobileApi } from '../services/MobileApi';
import { errorMessage } from '../services/errors';

export default function DocumentUploadScreen(): React.JSX.Element {
  const [documents, setDocuments] = useState<DocumentRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setDocuments(await MobileApi.documents());
    } catch (cause) {
      setError(errorMessage(cause, 'Request failed'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const upload = useCallback(async () => {
    setUploading(true);
    setError(null);
    try {
      const session = await MobileApi.createKycSession();
      const pending = await MobileApi.beginDocumentUpload(session.id, 'passport', 'passport.png');
      // The presigned upload itself happens out-of-band (storage SDK); the
      // backend confirms persistence via the complete call.
      await MobileApi.completeDocumentUpload(session.id, pending.documentId);
      setDocuments(await MobileApi.documents());
    } catch (cause) {
      setError(errorMessage(cause, 'Upload failed'));
    } finally {
      setUploading(false);
    }
  }, []);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text accessibilityRole="header" style={styles.title}>Document upload</Text>
      {loading && <ActivityIndicator accessibilityLabel="Loading server data" />}
      {error && <Text style={styles.error}>{error}</Text>}
      {documents && (
        <Text style={styles.data} selectable>
          {JSON.stringify(documents, null, 2)}
        </Text>
      )}
      <Button
        title={uploading ? 'Uploading...' : 'Upload passport'}
        onPress={() => { void upload(); }}
        disabled={uploading}
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flexGrow: 1, padding: 20, gap: 16 },
  title: { fontSize: 24, fontWeight: '700' },
  error: { color: '#b91c1c' },
  data: { fontFamily: 'monospace', color: '#102a43' },
});
