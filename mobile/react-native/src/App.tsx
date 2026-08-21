/**
 * Fraud Fusion Mobile App
 * Main application component with navigation and state management
 */

import React, { useEffect, useState } from 'react';
import {
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
import { logger } from './services/logger';

// Types
import { RootStackParamList, MainTabParamList } from './types/navigation';

const Stack = createStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<MainTabParamList>();

/**
 * Main Tab Navigator
 */
function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
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
        },
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
    initializeApplication();
  }, []);

  /**
   * Initialize application
   */
  const initializeApplication = async () => {
    try {
      // Initialize app services
      await initializeApp();

      // Setup push notifications
      await setupPushNotifications();

      // Check biometric support
      const biometricSupported = await checkBiometricSupport();
      logger.info('biometric.support_checked', { supported: biometricSupported });

      // Check authentication status
      // const authStatus = await checkAuthStatus();
      // setIsAuthenticated(authStatus);

      // Simulate loading
      setTimeout(() => {
        setIsLoading(false);
      }, 2000);

    } catch (error) {
      logger.error('app.initialization_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
      setIsLoading(false);
    }
  };

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
