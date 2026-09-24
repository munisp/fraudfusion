/**
 * Fraud Fusion Mobile App
 * Main application component with navigation and state management
 */

import React, { useEffect, useState } from 'react';
import {
  AppState,
  InteractionManager,
  SafeAreaView,
  StatusBar,
  StyleSheet,
  useColorScheme,
} from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Redux store
import { store, persistor } from './store';

// Screens
import SplashScreen from './screens/SplashScreen';
import LoginScreen from './screens/LoginScreen';
import RegisterScreen from './screens/RegisterScreen';
import DashboardScreen from './screens/DashboardScreen';
import KYCStartScreen from './screens/KYCStartScreen';
import KYCDocumentScreen from './screens/KYCDocumentScreen';
import KYCBiometricScreen from './screens/KYCBiometricScreen';
import KYCStatusScreen from './screens/KYCStatusScreen';
import DocumentUploadScreen from './screens/DocumentUploadScreen';
import DocumentListScreen from './screens/DocumentListScreen';
import ProfileScreen from './screens/ProfileScreen';
import SettingsScreen from './screens/SettingsScreen';
import NotificationsScreen from './screens/NotificationsScreen';
import VideoKYCScreen from './screens/VideoKYCScreen';
import FraudAlertsScreen from './screens/FraudAlertsScreen';

// Services
import { initializeApp } from './services/AppService';
import { setupPushNotifications } from './services/NotificationService';
import { checkBiometricSupport } from './services/BiometricService';
import { AuthService } from './services/AuthService';
import { logger } from './services/logger';

// Types
import { RootStackParamList, MainTabParamList } from './types/navigation';

const Stack = createStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<MainTabParamList>();

// Hoisted to module scope so the navigator does not recreate the icon closure
// on every render (M5 memoization fix).
function tabBarIcon(routeName: string) {
  return function TabBarIcon({ focused, color, size }: { focused: boolean; color: string; size: number }) {
    let iconName: string;

    switch (routeName) {
      case 'Dashboard':
        iconName = focused ? 'view-dashboard' : 'view-dashboard-outline';
        break;
      case 'KYC':
        iconName = focused ? 'account-check' : 'account-check-outline';
        break;
      case 'Documents':
        iconName = focused ? 'file-document' : 'file-document-outline';
        break;
      case 'Alerts':
        iconName = focused ? 'alert-circle' : 'alert-circle-outline';
        break;
      case 'Profile':
        iconName = focused ? 'account' : 'account-outline';
        break;
      default:
        iconName = 'circle';
    }

    return <Icon name={iconName} size={size} color={color} />;
  };
}

/**
 * Main Tab Navigator
 */
function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: tabBarIcon(route.name),
        tabBarActiveTintColor: '#1e40af',
        tabBarInactiveTintColor: '#6b7280',
        headerShown: false,
      })}
    >
      <Tab.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{ title: 'Dashboard' }}
      />
      <Tab.Screen
        name="KYC"
        component={KYCStartScreen}
        options={{ title: 'KYC Verification' }}
      />
      <Tab.Screen
        name="Documents"
        component={DocumentListScreen}
        options={{ title: 'Documents' }}
      />
      <Tab.Screen
        name="Alerts"
        component={FraudAlertsScreen}
        options={{ title: 'Fraud Alerts' }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileScreen}
        options={{ title: 'Profile' }}
      />
    </Tab.Navigator>
  );
}

/**
 * Main App Component
 */
function App(): React.JSX.Element {
  const isDarkMode = useColorScheme() === 'dark';
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    let cancelled = false;

    /**
     * Initialize application: only the work required to render the first
     * frame runs on the splash path. Push-notification registration and
     * biometric capability probing are deferred until after interactions.
     */
    const initializeApplication = async () => {
      try {
        // Critical: runtime config validation + foreground message subscription.
        await initializeApp();

        // Restore the persisted session so returning users skip Login.
        const session = await AuthService.restoreSession();
        if (!cancelled) {
          setIsAuthenticated(session !== null);
        }

        // Non-critical init deferred until after the first frame is interactive.
        InteractionManager.runAfterInteractions(() => {
          void setupPushNotifications().catch((error: unknown) => {
            logger.warn('notifications.setup_deferred_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
          });
          void checkBiometricSupport()
            .then((supported) => logger.info('biometric.support_checked', { supported }))
            .catch((error: unknown) => {
              logger.warn('biometric.support_check_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
            });
        });
      } catch (error) {
        logger.error('app.initialization_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
      } finally {
        // Splash gates on real readiness only — no artificial delay.
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    void initializeApplication();

    // Device-integrity re-check on every return to foreground: a critical
    // verdict wipes the local session (in AuthService) and drops the user
    // back to the login gate.
    const subscription = AppState.addEventListener('change', (nextState) => {
      if (nextState !== 'active' || cancelled) return;
      void AuthService.verifyDeviceIntegrity('foreground')
        .then((trusted) => {
          if (!trusted && !cancelled) {
            setIsAuthenticated(false);
          }
        })
        .catch((error: unknown) => {
          logger.warn('auth.foreground_integrity_check_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
        });
    });

    return () => {
      cancelled = true;
      subscription.remove();
    };
  }, []);

  const backgroundStyle = {
    backgroundColor: isDarkMode ? '#1f2937' : '#ffffff',
    flex: 1,
  };

  return (
    <Provider store={store}>
      <PersistGate loading={null} persistor={persistor}>
        <SafeAreaView style={backgroundStyle}>
          <StatusBar
            barStyle={isDarkMode ? 'light-content' : 'dark-content'}
            backgroundColor={backgroundStyle.backgroundColor}
          />
          <NavigationContainer>
            <Stack.Navigator
              screenOptions={{
                headerShown: false,
              }}
            >
              {isLoading ? (
                <Stack.Screen name="Splash" component={SplashScreen} />
              ) : !isAuthenticated ? (
                <>
                  <Stack.Screen name="Login" component={LoginScreen} />
                  <Stack.Screen name="Register" component={RegisterScreen} />
                </>
              ) : (
                <>
                  <Stack.Screen name="Main" component={MainTabs} />
                  <Stack.Screen name="KYCDocument" component={KYCDocumentScreen} />
                  <Stack.Screen name="KYCBiometric" component={KYCBiometricScreen} />
                  <Stack.Screen name="KYCStatus" component={KYCStatusScreen} />
                  <Stack.Screen name="DocumentUpload" component={DocumentUploadScreen} />
                  <Stack.Screen name="Settings" component={SettingsScreen} />
                  <Stack.Screen name="Notifications" component={NotificationsScreen} />
                  <Stack.Screen name="VideoKYC" component={VideoKYCScreen} />
                </>
              )}
            </Stack.Navigator>
          </NavigationContainer>
        </SafeAreaView>
      </PersistGate>
    </Provider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});

export default App;
