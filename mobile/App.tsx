import 'react-native-gesture-handler';
import React, { useEffect, useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { StripeProvider } from '@stripe/stripe-react-native';
import { AppNavigator } from './src/navigation/AppNavigator';
import { stripeAPI } from './src/services/api';

export default function App() {
  const [stripeKey, setStripeKey] = useState<string | null>(null);

  useEffect(() => {
    stripeAPI.getConfig()
      .then((res) => setStripeKey(res.data.publishableKey))
      .catch(() => {
        // Stripe not configured — payments will show an error at checkout
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
