import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Button, ScrollView, StyleSheet, Text } from 'react-native';
import { MobileApi, Profile } from '../services/MobileApi';
import { BiometricService } from '../services/BiometricService';
import { errorMessage } from '../services/errors';

type EnrollmentPhase = 'idle' | 'scanning' | 'success' | 'failure';

export default function KYCBiometricScreen(): React.JSX.Element {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [phase, setPhase] = useState<EnrollmentPhase>('idle');

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

  const enroll = useCallback(async () => {
    setPhase('scanning');
    setError(null);
    try {
      if (!(await BiometricService.isAvailable())) {
        throw new Error('Biometric sensor is not available on this device');
      }
      await BiometricService.authenticate('Scan your fingerprint or face to enroll biometrics');
      const session = await MobileApi.createKycSession();
      const challenge = await MobileApi.biometricChallenge(session.id);
      await MobileApi.submitBiometric(session.id, challenge.challengeId);
      setPhase('success');
    } catch (cause) {
      setError(errorMessage(cause, 'Biometric enrollment failed'));
      setPhase('failure');
    }
  }, []);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text accessibilityRole="header" style={styles.title}>Biometric verification</Text>
      {loading && <ActivityIndicator accessibilityLabel="Loading server data" />}
      {error && <Text style={styles.error}>{error}</Text>}
      {profile && (
        <Text style={styles.data}>
          Biometric login on this account: {profile.biometricEnabled ? 'enabled' : 'disabled'}
        </Text>
      )}
      <Text style={styles.status}>Enrollment status: {phase}</Text>
      <Button
        title={phase === 'scanning' ? 'Scanning...' : 'Start biometric enrollment'}
        onPress={() => { void enroll(); }}
        disabled={loading || phase === 'scanning'}
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
