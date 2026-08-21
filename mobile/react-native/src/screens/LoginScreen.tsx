import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Alert, StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { StackNavigationProp } from '@react-navigation/stack';
import { useNavigation } from '@react-navigation/native';
import { AuthService } from '../services/AuthService';
import { BiometricService } from '../services/BiometricService';
import { logger } from '../services/logger';
import { RootStackParamList } from '../navigation/types';
import { useAppDispatch, useAppSelector } from '../store/hooks';
import { authSlice } from '../store/state-management-fixes';

type LoginNavigation = StackNavigationProp<RootStackParamList, 'Login'>;

export default function LoginScreen(): React.JSX.Element {
  const navigation = useNavigation<LoginNavigation>();
  const dispatch = useAppDispatch();
  const authLoading = useAppSelector((state) => state.auth.isLoading);
  const [biometricAvailable, setBiometricAvailable] = useState(false);

  useEffect(() => {
    let active = true;
    BiometricService.isAvailable()
      .then((available) => active && setBiometricAvailable(available))
      .catch((error) => logger.warn('biometric.availability_check_failed', {
        reason: error instanceof Error ? error.message : 'unknown_error',
      }));
    return () => {
      active = false;
    };
  }, []);

  const completeSession = useCallback((session: Awaited<ReturnType<typeof AuthService.signIn>>) => {
    dispatch(authSlice.actions.setAuth({
      user: session.user,
      token: session.accessToken,
      timestamp: Date.now(),
    }));
    navigation.reset({ index: 0, routes: [{ name: 'Dashboard' }] });
  }, [dispatch, navigation]);

  const handleOidcSignIn = useCallback(async () => {
    dispatch(authSlice.actions.setAuthLoading(true));
    try {
      completeSession(await AuthService.signIn());
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Sign in could not be completed';
      logger.error('auth.oidc_sign_in_failed', { reason: message });
      dispatch(authSlice.actions.setAuthError(message));
      Alert.alert('Sign in unavailable', message);
    } finally {
      dispatch(authSlice.actions.setAuthLoading(false));
    }
  }, [completeSession, dispatch]);

  const handleBiometricUnlock = useCallback(async () => {
    dispatch(authSlice.actions.setAuthLoading(true));
    try {
      await BiometricService.authenticate();
      const existing = await AuthService.restoreSession();
      if (!existing) {
        throw new Error('No prior secure session is available. Sign in with your identity provider first.');
      }
      completeSession(await AuthService.refreshSession(existing));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Biometric authentication failed';
      logger.warn('auth.biometric_unlock_failed', { reason: message });
      Alert.alert('Biometric sign in unavailable', message);
    } finally {
      dispatch(authSlice.actions.setAuthLoading(false));
    }
  }, [completeSession, dispatch]);

  return (
    <View style={styles.container}>
      <Text accessibilityRole="header" style={styles.title}>FraudFusion</Text>
      <Text style={styles.subtitle}>Sign in through your organization’s secure identity provider.</Text>
      <TouchableOpacity
        accessibilityRole="button"
        accessibilityLabel="Sign in securely"
        disabled={authLoading}
        onPress={handleOidcSignIn}
        style={[styles.primaryButton, authLoading && styles.disabledButton]}
      >
        {authLoading ? <ActivityIndicator color="#ffffff" /> : <Text style={styles.primaryButtonText}>Sign in securely</Text>}
      </TouchableOpacity>
      {biometricAvailable && (
        <TouchableOpacity
          accessibilityRole="button"
          accessibilityLabel="Unlock with biometrics"
          disabled={authLoading}
          onPress={handleBiometricUnlock}
          style={[styles.secondaryButton, authLoading && styles.disabledButton]}
        >
          <Text style={styles.secondaryButtonText}>Unlock with biometrics</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', padding: 24, backgroundColor: '#ffffff' },
  title: { fontSize: 32, fontWeight: '700', color: '#102a43', marginBottom: 12 },
  subtitle: { fontSize: 16, lineHeight: 24, color: '#486581', marginBottom: 32 },
  primaryButton: { minHeight: 52, justifyContent: 'center', alignItems: 'center', borderRadius: 8, backgroundColor: '#0f5ea8', marginBottom: 12 },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  secondaryButton: { minHeight: 52, justifyContent: 'center', alignItems: 'center', borderRadius: 8, borderWidth: 1, borderColor: '#0f5ea8' },
  secondaryButtonText: { color: '#0f5ea8', fontSize: 16, fontWeight: '600' },
  disabledButton: { opacity: 0.6 },
});
