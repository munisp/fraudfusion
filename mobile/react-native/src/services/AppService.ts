import { NotificationService } from './NotificationService';
import { logger } from './logger';

let foregroundUnsubscribe: (() => void) | undefined;

export async function initializeApp(): Promise<void> {
  const authConfig = (globalThis as typeof globalThis & { __FRAUDFUSION_AUTH_CONFIG__?: unknown }).__FRAUDFUSION_AUTH_CONFIG__;
  const apiConfig = (globalThis as typeof globalThis & { __FRAUDFUSION_API_CONFIG__?: unknown }).__FRAUDFUSION_API_CONFIG__;
  if (!authConfig || !apiConfig) {
    throw new Error('Mobile identity-provider and API runtime configuration must be set before startup');
  }
  if (!foregroundUnsubscribe) {
    foregroundUnsubscribe = NotificationService.subscribeForegroundMessages();
  }
  logger.info('app.initialized');
}

export function shutdownApp(): void {
  foregroundUnsubscribe?.();
  foregroundUnsubscribe = undefined;
  logger.info('app.shutdown');
}
