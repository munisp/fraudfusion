import notifee, { AndroidImportance, AuthorizationStatus, EventType } from '@notifee/react-native';
import { AuthorizationStatus as MessagingAuthorizationStatus, deleteToken, getMessaging, getToken, onMessage, registerDeviceForRemoteMessages, requestPermission, type RemoteMessage } from '@react-native-firebase/messaging';
import axios from 'axios';
import { AuthService } from './AuthService';
import { logger } from './logger';

interface ApiConfig {
  baseUrl: string;
}

declare global {
  var __FRAUDFUSION_API_CONFIG__: ApiConfig | undefined;
}

function apiBaseUrl(): string {
  const runtime = globalThis as typeof globalThis & { __FRAUDFUSION_API_CONFIG__?: ApiConfig };
  const baseUrl = runtime.__FRAUDFUSION_API_CONFIG__?.baseUrl;
  if (!baseUrl) {
    throw new Error('Mobile API base URL is required for push-token registration');
  }
  return baseUrl.replace(/\/$/, '');
}

async function authenticatedHeaders(): Promise<Record<string, string>> {
  const session = await AuthService.restoreSession();
  if (!session) {
    throw new Error('A verified mobile session is required to register a push token');
  }
  return { Authorization: `Bearer ${session.accessToken}` };
}

const messagingClient = getMessaging();

async function ensureNotificationPermission(): Promise<void> {
  const authorization = await requestPermission(messagingClient);
  const granted = authorization === MessagingAuthorizationStatus.AUTHORIZED
    || authorization === MessagingAuthorizationStatus.PROVISIONAL;
  if (!granted) {
    throw new Error('Notification permission was not granted');
  }
}

async function ensureAndroidChannel(): Promise<string> {
  return notifee.createChannel({
    id: 'security-alerts',
    name: 'Security alerts',
    importance: AndroidImportance.HIGH,
  });
}

export const NotificationService = {
  async registerCurrentDevice(): Promise<void> {
    await ensureNotificationPermission();
    await registerDeviceForRemoteMessages(messagingClient);
    const token = await getToken(messagingClient);
    if (!token) {
      throw new Error('Push provider did not return a device token');
    }
    await axios.post(
      `${apiBaseUrl()}/devices/push-tokens`,
      { token, provider: 'fcm' },
      { headers: await authenticatedHeaders(), timeout: 10_000 },
    );
    logger.info('notifications.device_token_registered');
  },

  async unregisterCurrentDevice(): Promise<void> {
    const token = await getToken(messagingClient);
    if (!token) return;
    await axios.delete(`${apiBaseUrl()}/devices/push-tokens`, {
      headers: await authenticatedHeaders(),
      data: { token, provider: 'fcm' },
      timeout: 10_000,
    });
    await deleteToken(messagingClient);
    logger.info('notifications.device_token_unregistered');
  },

  subscribeForegroundMessages(): () => void {
    return onMessage(messagingClient, async (message: RemoteMessage) => {
      await this.displayForegroundMessage(message);
    });
  },

  async displayForegroundMessage(message: RemoteMessage): Promise<void> {
    const channelId = await ensureAndroidChannel();
    await notifee.displayNotification({
      title: message.notification?.title ?? 'FraudFusion notification',
      body: message.notification?.body ?? 'You have a new security update.',
      data: message.data,
      android: { channelId, pressAction: { id: 'default' } },
    });
    logger.info('notifications.foreground_message_displayed', { messageId: message.messageId });
  },

  subscribeInteractionEvents(onOpen: (data: Record<string, string> | undefined) => void): () => void {
    return notifee.onForegroundEvent(({ type, detail }) => {
      if (type === EventType.PRESS) {
        const data = detail.notification?.data;
        onOpen(data ? Object.fromEntries(Object.entries(data).map(([key, value]) => [key, String(value)])) : undefined);
      }
    });
  },

  async notificationPermissionGranted(): Promise<boolean> {
    const settings = await notifee.getNotificationSettings();
    return settings.authorizationStatus === AuthorizationStatus.AUTHORIZED
      || settings.authorizationStatus === AuthorizationStatus.PROVISIONAL;
  },
};

export async function setupPushNotifications(): Promise<void> {
  await NotificationService.registerCurrentDevice();
}
