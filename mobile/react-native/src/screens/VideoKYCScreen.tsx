import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Button, ScrollView, StyleSheet, Text } from 'react-native';
import { KycSession, MobileApi, Profile } from '../services/MobileApi';
import { errorMessage } from '../services/errors';

export default function VideoKYCScreen(): React.JSX.Element {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [session, setSession] = useState<KycSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setProfile(await MobileApi.profile());
    } catch (cause) {
      setError(errorMessage(cause, 'Request failed'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const submitVideo = useCallback(async () => {
    setSubmitting(true);
    setError(null);
    try {
      const kycSession = await MobileApi.createKycSession();
      const updated = await MobileApi.submitVideoKyc(kycSession.id, `recording-${kycSession.id}`);
      setSession(updated);
    } catch (cause) {
      setError(errorMessage(cause, 'Video KYC submission failed'));
    } finally {
      setSubmitting(false);
    }
  }, []);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text accessibilityRole="header" style={styles.title}>Video KYC</Text>
      {loading && <ActivityIndicator accessibilityLabel="Loading server data" />}
      {error && <Text style={styles.error}>{error}</Text>}
      {profile && (
        <Text style={styles.data}>
          Video identification for account {profile.id}
        </Text>
      )}
      {session && (
        <Text style={styles.status}>KYC session {session.id}: {session.status}</Text>
      )}
      <Button
        title={submitting ? 'Submitting...' : 'Submit recorded video session'}
        onPress={() => { void submitVideo(); }}
        disabled={submitting}
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flexGrow: 1, padding: 20, gap: 16 },
  title: { fontSize: 24, fontWeight: '700' },
  status: { fontSize: 16, fontWeight: '600', color: '#102a43' },
  error: { color: '#b91c1c' },
  data: { color: '#102a43' },
});
