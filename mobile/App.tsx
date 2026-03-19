import 'react-native-gesture-handler';
import React, { useEffect, useRef, useState } from 'react';
import { Platform } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { StripeProvider } from '@stripe/stripe-react-native';
import { AppNavigator, navigationRef } from './src/navigation/AppNavigator';
import { stripeAPI, pushAPI } from './src/services/api';

// Push notifications — lazily imported so the build still works
// if expo-notifications isn't installed yet.
let Notifications: typeof import('expo-notifications') | null = null;
let Device: typeof import('expo-device') | null = null;
try {
  Notifications = require('expo-notifications');
  Device        = require('expo-device');
} catch (_) { /* not installed */ }

const ENV_STRIPE_KEY = process.env.EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY;

// ─── Push registration ────────────────────────────────────────────────────────

async function registerForPushNotificationsAsync(): Promise<string | null> {
  if (!Notifications || !Device) return null;
  if (!Device.isDevice) return null; // must be a real device

  const { status: existing } = await Notifications.getPermissionsAsync();
  let finalStatus = existing;
  if (existing !== 'granted') {
    const { status } = await Notifications.requestPermissionsAsync();
    finalStatus = status;
  }
  if (finalStatus !== 'granted') return null;

  const tokenData = await Notifications.getExpoPushTokenAsync();
  return tokenData.data;
}

// ─── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [stripeKey, setStripeKey] = useState<string | null>(ENV_STRIPE_KEY ?? null);
  const notificationListener     = useRef<any>();
  const responseListener          = useRef<any>();

  // Stripe key
  useEffect(() => {
    if (ENV_STRIPE_KEY) return;
    stripeAPI.getConfig()
      .then((res) => setStripeKey(res.data.publishableKey))
      .catch(() => { console.warn('Stripe publishable key not available'); });
  }, []);

  // Push notifications
  useEffect(() => {
    if (!Notifications) return;

    // Show banners while app is in foreground
    Notifications.setNotificationHandler({
      handleNotification: async () => ({
        shouldShowAlert: true,
        shouldPlaySound: true,
        shouldSetBadge:  true,
      }),
    });

    // Register and save token
    registerForPushNotificationsAsync().then((token) => {
      if (token) pushAPI.saveToken(token).catch(() => {});
    });

    // Handle notification tap → navigate to Trips
    responseListener.current = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data as any;
      if (data?.screen === 'Trips') {
        navigationRef.current?.navigate('Main');
        // A small delay to let the navigator mount before switching tab
        setTimeout(() => {
          (navigationRef.current as any)?.navigate('Trips');
        }, 500);
      }
    });

    return () => {
      if (notificationListener.current) Notifications!.removeNotificationSubscription(notificationListener.current);
      if (responseListener.current)     Notifications!.removeNotificationSubscription(responseListener.current);
    };
  }, []);

  return (
    <StripeProvider publishableKey={stripeKey ?? 'pk_test_placeholder'}>
      <StatusBar style="light" />
      <AppNavigator />
    </StripeProvider>
  );
}
