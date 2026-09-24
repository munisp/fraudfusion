import React, { memo } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { ListApiScreen } from './ListApiScreen';
import { MobileApi, NotificationRecord } from '../services/MobileApi';

// Memoized row: only re-renders when its notification object identity changes.
const NotificationRow = memo(function NotificationRow({ notification }: { notification: NotificationRecord }): React.JSX.Element {
  return (
    <View style={styles.row}>
      <Text style={styles.rowTitle}>
        {notification.readAt ? '' : '● '}{notification.title}
      </Text>
      <Text style={styles.body}>{notification.body}</Text>
      <Text style={styles.date}>{new Date(notification.createdAt).toLocaleString()}</Text>
    </View>
  );
});

// Module-level stable references so FlatList props never change identity.
const renderNotification = (item: NotificationRecord): React.ReactElement => <NotificationRow notification={item} />;
const notificationKey = (item: NotificationRecord): string => item.id;

export default function NotificationsScreen(): React.JSX.Element {
  return (
    <ListApiScreen
      title="Notifications"
      load={MobileApi.notifications}
      keyExtractor={notificationKey}
      renderItem={renderNotification}
      emptyLabel="No notifications."
    />
  );
}

const styles = StyleSheet.create({
  row: { paddingVertical: 12, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#d1d5db' },
  rowTitle: { fontSize: 16, fontWeight: '600', color: '#111827' },
  body: { color: '#374151', marginTop: 2 },
  date: { color: '#6b7280', fontSize: 12, marginTop: 2 },
});
