import React, { useEffect, useRef, useState } from 'react';
import { NavigationContainer, NavigationContainerRef } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Ionicons } from '@expo/vector-icons';
import { View, StyleSheet, TouchableOpacity, ActivityIndicator } from 'react-native';

import { WelcomeScreen } from '../screens/auth/WelcomeScreen';
import { LoginScreen } from '../screens/auth/LoginScreen';
import { RegisterScreen } from '../screens/auth/RegisterScreen';
import { OnboardingScreen } from '../screens/onboarding/OnboardingScreen';
import { HomeScreen } from '../screens/home/HomeScreen';
import { TripsScreen } from '../screens/home/TripsScreen';
import { ProfileScreen } from '../screens/profile/ProfileScreen';
import { GeneratePackageScreen } from '../screens/packages/GeneratePackageScreen';
import { PackageDetailScreen } from '../screens/packages/PackageDetailScreen';
import { PlansScreen } from '../screens/subscription/PlansScreen';
import { PaymentScreen } from '../screens/subscription/PaymentScreen';
import AIChatScreen from '../screens/chat/AIChatScreen';
import { PrivacySecurityScreen } from '../screens/profile/PrivacySecurityScreen';
import { NotificationSettingsScreen } from '../screens/profile/NotificationSettingsScreen';
import { AdminPanelScreen } from '../screens/admin/AdminPanelScreen';
import { CreatePackageScreen } from '../screens/admin/CreatePackageScreen';

import { RootStackParamList, MainTabParamList } from '../types';
import { COLORS, FONTS } from '../constants/theme';
import { useStore } from '../store/useStore';

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<MainTabParamList>();

// Exported so push notification tap handler (App.tsx) can navigate
export const navigationRef = React.createRef<NavigationContainerRef<RootStackParamList>>();

const GenerateTabButton = ({ onPress }: { onPress: () => void }) => (
  <TouchableOpacity style={tabStyles.generateBtn} onPress={onPress} activeOpacity={0.85}>
    <Ionicons name="sparkles" size={22} color={COLORS.white} />
  </TouchableOpacity>
);

const tabStyles = StyleSheet.create({
  generateBtn: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: COLORS.secondary,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 24,
    shadowColor: COLORS.secondary,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 8,
  },
});

function MainTabs() {
  const { unreadCount } = useStore();

  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: {
          backgroundColor: COLORS.surface,
          borderTopColor: COLORS.border,
          borderTopWidth: 1,
          height: 80,
          paddingBottom: 16,
          paddingTop: 8,
        },
        tabBarActiveTintColor: COLORS.secondary,
        tabBarInactiveTintColor: COLORS.textMuted,
        tabBarLabelStyle: {
          fontSize: FONTS.sizes.xs,
          fontWeight: '600',
          marginTop: 2,
        },
        tabBarIcon: ({ color, focused }) => {
          const icons: Record<string, [keyof typeof Ionicons.glyphMap, keyof typeof Ionicons.glyphMap]> = {
            Home:    ['home',                   'home-outline'],
            AIChat:  ['chatbubble-ellipses',    'chatbubble-ellipses-outline'],
            Generate:['sparkles',               'sparkles-outline'],
            Trips:   ['airplane',               'airplane-outline'],
            Profile: ['person',                 'person-outline'],
          };
          const [activeIcon, inactiveIcon] = icons[route.name] || ['ellipse', 'ellipse-outline'];
          return <Ionicons name={focused ? activeIcon : inactiveIcon} size={22} color={color} />;
        },
      })}
    >
      <Tab.Screen name="Home" component={HomeScreen} />
      <Tab.Screen
        name="AIChat"
        component={AIChatScreen}
        options={{ tabBarLabel: 'Assistant' }}
      />
      <Tab.Screen
        name="Generate"
        component={GeneratePackageScreen}
        options={{
          tabBarLabel: 'Generate',
          tabBarIcon: () => null,
          tabBarButton: (props) => (
            <GenerateTabButton onPress={props.onPress as () => void} />
          ),
        }}
      />
      <Tab.Screen
        name="Trips"
        component={TripsScreen}
        options={{
          tabBarBadge: unreadCount > 0 ? unreadCount : undefined,
          tabBarBadgeStyle: { backgroundColor: COLORS.accent, color: '#000', fontSize: 10 },
        }}
      />
      <Tab.Screen name="Profile" component={ProfileScreen} />
    </Tab.Navigator>
  );
}

export function AppNavigator() {
  const { isAuthenticated, isOnboardingComplete, loadFromStorage } = useStore();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFromStorage().finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <View style={{ flex: 1, backgroundColor: COLORS.background, alignItems: 'center', justifyContent: 'center' }}>
        <ActivityIndicator color={COLORS.secondary} size="large" />
      </View>
    );
  }

  const initialRoute = (): keyof RootStackParamList => {
    if (!isAuthenticated) return 'Welcome';
    if (!isOnboardingComplete) return 'Onboarding';
    return 'Main';
  };

  return (
    <NavigationContainer ref={navigationRef}>
      <Stack.Navigator
        initialRouteName={initialRoute()}
        screenOptions={{ headerShown: false, animation: 'slide_from_right' }}
      >
        <Stack.Screen name="Welcome" component={WelcomeScreen} />
        <Stack.Screen name="Login" component={LoginScreen} />
        <Stack.Screen name="Register" component={RegisterScreen} />
        <Stack.Screen name="Onboarding" component={OnboardingScreen} />
        <Stack.Screen name="Main" component={MainTabs} />
        <Stack.Screen name="PackageDetail" component={PackageDetailScreen} options={{ animation: 'slide_from_bottom' }} />
        <Stack.Screen name="GeneratePackage" component={GeneratePackageScreen} />
        <Stack.Screen name="Plans" component={PlansScreen} />
        <Stack.Screen name="Payment" component={PaymentScreen} />
        <Stack.Screen name="PrivacySecurity" component={PrivacySecurityScreen} />
        <Stack.Screen name="NotificationSettings" component={NotificationSettingsScreen} />
        <Stack.Screen name="AdminPanel" component={AdminPanelScreen} />
        <Stack.Screen name="CreatePackage" component={CreatePackageScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
