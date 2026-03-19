import 'react-native-gesture-handler';
import React, { useEffect, useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { StripeProvider } from '@stripe/stripe-react-native';
import { AppNavigator } from './src/navigation/AppNavigator';
import { stripeAPI } from './src/services/api';

const ENV_STRIPE_KEY = process.env.EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY;

export default function App() {
  const [stripeKey, setStripeKey] = useState<string | null>(ENV_STRIPE_KEY ?? null);

  useEffect(() => {
    if (ENV_STRIPE_KEY) return; // already have it from env
    stripeAPI.getConfig()
      .then((res) => setStripeKey(res.data.publishableKey))
      .catch(() => {
        console.warn('Stripe publishable key not available');
      });
  }, []);

  return (
    <StripeProvider publishableKey={stripeKey ?? 'pk_test_placeholder'}>
      <StatusBar style="light" />
      <AppNavigator />
    </StripeProvider>
  );
}
