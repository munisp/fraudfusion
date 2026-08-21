import ReactNativeBiometrics from 'react-native-biometrics';
import { logger } from './logger';

export class BiometricNotAvailableError extends Error {}
export class BiometricAuthenticationError extends Error {}

const biometrics = new ReactNativeBiometrics({ allowDeviceCredentials: false });

export const BiometricService = {
  async isAvailable(): Promise<boolean> {
    const result = await biometrics.isSensorAvailable();
    return result.available;
  },

  async authenticate(reason = 'Authenticate to access FraudFusion'): Promise<void> {
    const availability = await biometrics.isSensorAvailable();
    if (!availability.available) {
      throw new BiometricNotAvailableError(availability.error ?? 'Biometric authentication is unavailable');
    }
    const result = await biometrics.simplePrompt({ promptMessage: reason, cancelButtonText: 'Cancel' });
    if (!result.success) {
      logger.warn('biometric.authentication_rejected');
      throw new BiometricAuthenticationError('Biometric authentication was not completed');
    }
    logger.info('biometric.authentication_succeeded');
  },
};

export async function checkBiometricSupport(): Promise<boolean> {
  return BiometricService.isAvailable();
}
