import React, { useEffect, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  Animated,
  Dimensions,
  Image,
  StatusBar,
} from 'react-native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

const { width, height } = Dimensions.get('window');

type Props = {
  navigation: NativeStackNavigationProp<RootStackParamList, 'Welcome'>;
};

const DESTINATIONS = [
  { name: 'London', uri: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=800' },
  { name: 'Tokyo', uri: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=800' },
  { name: 'Paris', uri: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=800' },
];

export const WelcomeScreen: React.FC<Props> = ({ navigation }) => {
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const slideAnim = useRef(new Animated.Value(40)).current;
  const scaleAnim = useRef(new Animated.Value(1.1)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeAnim, { toValue: 1, duration: 1000, useNativeDriver: true }),
      Animated.timing(slideAnim, { toValue: 0, duration: 800, useNativeDriver: true }),
      Animated.timing(scaleAnim, { toValue: 1, duration: 1200, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Background Image */}
      <Animated.View style={[styles.bgContainer, { transform: [{ scale: scaleAnim }] }]}>
        <Image
          source={{ uri: DESTINATIONS[0].uri }}
          style={styles.bgImage}
          resizeMode="cover"
        />
        <View style={styles.bgOverlay} />
      </Animated.View>

      {/* Content */}
      <Animated.View
        style={[
          styles.content,
          { opacity: fadeAnim, transform: [{ translateY: slideAnim }] },
        ]}
      >
        {/* Logo / Brand */}
        <View style={styles.logoContainer}>
          <View style={styles.logoBadge}>
            <Text style={styles.logoIcon}>✦</Text>
          </View>
          <Text style={styles.logoText}>Travel Odyssey</Text>
        </View>

        {/* Hero Text */}
        <View style={styles.heroText}>
          <Text style={styles.headline}>Your Journey,</Text>
          <Text style={styles.headlineAccent}>Perfectly Crafted</Text>
          <Text style={styles.subheadline}>
            Handcrafted travel experiences tailored to your tastes, budget, and dreams.
          </Text>
        </View>

        {/* Stats Row */}
        <View style={styles.statsRow}>
          {[
            { value: '150+', label: 'Destinations' },
            { value: '10K+', label: 'Happy Travelers' },
            { value: '4.9★', label: 'App Rating' },
          ].map((stat, i) => (
            <View key={i} style={styles.stat}>
              <Text style={styles.statValue}>{stat.value}</Text>
              <Text style={styles.statLabel}>{stat.label}</Text>
            </View>
          ))}
        </View>

        {/* CTA Buttons */}
        <View style={styles.buttons}>
          <Button
            label="Start Your Journey"
            onPress={() => navigation.navigate('Register')}
            variant="primary"
          />
          <Button
            label="I already have an account"
            onPress={() => navigation.navigate('Login')}
            variant="outline"
            style={{ marginTop: SPACING.sm }}
          />
        </View>
      </Animated.View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.background,
  },
  bgContainer: {
    ...StyleSheet.absoluteFillObject,
  },
  bgImage: {
    width: '100%',
    height: '100%',
  },
  bgOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(13, 10, 30, 0.72)',
  },
  content: {
    flex: 1,
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.xxxl + SPACING.xl,
    paddingBottom: SPACING.xxl,
    justifyContent: 'flex-end',
  },
  logoContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: SPACING.xxxl,
    gap: SPACING.sm,
  },
  logoBadge: {
    width: 36,
    height: 36,
    borderRadius: RADIUS.md,
    backgroundColor: COLORS.secondary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoIcon: {
    color: COLORS.white,
    fontSize: 18,
    fontWeight: '700',
  },
  logoText: {
    color: COLORS.white,
    fontSize: FONTS.sizes.lg,
    fontWeight: '700',
    letterSpacing: 1,
  },
  heroText: {
    marginBottom: SPACING.xl,
  },
  headline: {
    color: COLORS.white,
    fontSize: FONTS.sizes.display,
    fontWeight: '800',
    lineHeight: 44,
  },
  headlineAccent: {
    color: COLORS.accent,
    fontSize: FONTS.sizes.display,
    fontWeight: '800',
    lineHeight: 44,
    marginBottom: SPACING.md,
  },
  subheadline: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.md,
    lineHeight: 24,
    maxWidth: '90%',
  },
  statsRow: {
    flexDirection: 'row',
    backgroundColor: 'rgba(28, 21, 53, 0.8)',
    borderRadius: RADIUS.xl,
    padding: SPACING.md,
    marginBottom: SPACING.xl,
    gap: SPACING.md,
  },
  stat: {
    flex: 1,
    alignItems: 'center',
  },
  statValue: {
    color: COLORS.white,
    fontSize: FONTS.sizes.xl,
    fontWeight: '800',
  },
  statLabel: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.xs,
    marginTop: 2,
  },
  buttons: {
    gap: SPACING.sm,
  },
});
