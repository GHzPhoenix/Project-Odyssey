import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Animated,
  Dimensions,
  StatusBar,
  Alert,
  Image,
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { Ionicons } from '@expo/vector-icons';
import { RootStackParamList } from '../../types';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { preferencesAPI } from '../../services/api';

const { width, height } = Dimensions.get('window');

type Props = {
  navigation: NativeStackNavigationProp<RootStackParamList, 'Onboarding'>;
};

// ── Welcome slide images ──────────────────────────────────────────────
const WELCOME_IMAGES = [
  'https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?w=800',
  'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=800',
  'https://images.unsplash.com/photo-1570077188670-e3a8d69ac5ff?w=800',
];

// ── Step backgrounds ──────────────────────────────────────────────────
const STEP_BG = [
  'https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?w=800',
  'https://images.unsplash.com/photo-1500835556837-99ac94a94552?w=800',
  'https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=800',
  'https://images.unsplash.com/photo-1490818387583-1baba5e638af?w=800',
  'https://images.unsplash.com/photo-1519817787-69b35a7fd18e?w=800',
  'https://images.unsplash.com/photo-1469854523086-cc02fe5d8800?w=800',
];

const STEPS = [
  {
    id: 'style',
    title: 'Your Travel Style',
    subtitle: 'How do you like to explore the world?',
    emoji: '🌍',
    options: [
      { value: 'adventure', label: 'Adventure', icon: 'bicycle' as const, desc: 'Hiking & thrills' },
      { value: 'relaxed', label: 'Relaxed', icon: 'sunny' as const, desc: 'Beaches & slow days' },
      { value: 'cultural', label: 'Cultural', icon: 'library' as const, desc: 'History & art' },
      { value: 'foodie', label: 'Foodie', icon: 'restaurant' as const, desc: 'Cuisine & dining' },
      { value: 'luxury', label: 'Luxury', icon: 'diamond' as const, desc: 'Premium & exclusive' },
      { value: 'budget', label: 'Smart Saver', icon: 'wallet' as const, desc: 'Best value trips' },
    ],
    multiple: false,
  },
  {
    id: 'activities',
    title: 'Favourite Activities',
    subtitle: 'Pick everything you love doing on holiday',
    emoji: '🎯',
    options: [
      { value: 'museums', label: 'Museums', icon: 'business' as const, desc: '' },
      { value: 'beaches', label: 'Beaches', icon: 'water' as const, desc: '' },
      { value: 'hiking', label: 'Hiking', icon: 'walk' as const, desc: '' },
      { value: 'nightlife', label: 'Nightlife', icon: 'moon' as const, desc: '' },
      { value: 'shopping', label: 'Shopping', icon: 'bag-handle' as const, desc: '' },
      { value: 'cooking', label: 'Cooking Classes', icon: 'flame' as const, desc: '' },
      { value: 'sports', label: 'Sports', icon: 'football' as const, desc: '' },
      { value: 'photography', label: 'Photography', icon: 'camera' as const, desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'cuisine',
    title: 'Food Preferences',
    subtitle: 'What cuisine excites your palate?',
    emoji: '🍽️',
    options: [
      { value: 'italian', label: 'Italian', icon: 'pizza' as const, desc: '' },
      { value: 'asian', label: 'Asian', icon: 'fish' as const, desc: '' },
      { value: 'mediterranean', label: 'Mediterranean', icon: 'leaf' as const, desc: '' },
      { value: 'american', label: 'American', icon: 'fast-food' as const, desc: '' },
      { value: 'french', label: 'French', icon: 'wine' as const, desc: '' },
      { value: 'middle-eastern', label: 'Middle Eastern', icon: 'cafe' as const, desc: '' },
      { value: 'indian', label: 'Indian', icon: 'color-fill' as const, desc: '' },
      { value: 'local', label: 'Always Local', icon: 'location' as const, desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'dietary',
    title: 'Dietary Needs',
    subtitle: 'We\'ll make sure every meal suits you',
    emoji: '🥗',
    options: [
      { value: 'none', label: 'No restrictions', icon: 'checkmark-circle' as const, desc: '' },
      { value: 'vegetarian', label: 'Vegetarian', icon: 'leaf' as const, desc: '' },
      { value: 'vegan', label: 'Vegan', icon: 'nutrition' as const, desc: '' },
      { value: 'gluten-free', label: 'Gluten Free', icon: 'ban' as const, desc: '' },
      { value: 'halal', label: 'Halal', icon: 'shield-checkmark' as const, desc: '' },
      { value: 'kosher', label: 'Kosher', icon: 'star' as const, desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'budget',
    title: 'Your Budget',
    subtitle: 'What\'s your typical weekly travel budget?',
    emoji: '💰',
    options: [
      { value: 'budget', label: 'Budget', icon: 'trending-down' as const, desc: 'Under €1,500/week' },
      { value: 'moderate', label: 'Moderate', icon: 'trending-up' as const, desc: '€1,500 – €3,000/week' },
      { value: 'premium', label: 'Premium', icon: 'star' as const, desc: '€3,000 – €6,000/week' },
      { value: 'luxury', label: 'Luxury', icon: 'diamond' as const, desc: '€6,000+/week' },
    ],
    multiple: false,
  },
  {
    id: 'companions',
    title: 'Travel With',
    subtitle: 'Who do you usually travel with?',
    emoji: '👥',
    options: [
      { value: 'solo', label: 'Solo', icon: 'person' as const, desc: 'Just me & the world' },
      { value: 'partner', label: 'Partner', icon: 'heart' as const, desc: 'Romantic getaways' },
      { value: 'friends', label: 'Friends', icon: 'people' as const, desc: 'Squad adventures' },
      { value: 'family', label: 'Family', icon: 'home' as const, desc: 'Kid-friendly trips' },
    ],
    multiple: false,
  },
];

// ── Welcome Screen ────────────────────────────────────────────────────
const WelcomeSlide: React.FC<{ onStart: () => void; onSkip: () => void }> = ({ onStart, onSkip }) => {
  const bgAnim = useRef(new Animated.Value(0)).current;
  const [bgIndex, setBgIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      Animated.timing(bgAnim, { toValue: 0, duration: 300, useNativeDriver: true }).start(() => {
        setBgIndex((i) => (i + 1) % WELCOME_IMAGES.length);
        Animated.timing(bgAnim, { toValue: 1, duration: 800, useNativeDriver: true }).start();
      });
    }, 3500);
    Animated.timing(bgAnim, { toValue: 1, duration: 800, useNativeDriver: true }).start();
    return () => clearInterval(interval);
  }, []);

  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(40)).current;
  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 900, delay: 200, useNativeDriver: true }),
      Animated.timing(slideUp, { toValue: 0, duration: 700, delay: 200, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <View style={welcome.container}>
      <StatusBar barStyle="light-content" />

      {/* Background image with fade */}
      <Animated.View style={[StyleSheet.absoluteFillObject, { opacity: bgAnim }]}>
        <Image
          source={{ uri: WELCOME_IMAGES[bgIndex] }}
          style={StyleSheet.absoluteFillObject}
          resizeMode="cover"
        />
      </Animated.View>

      {/* Gradient overlay */}
      <LinearGradient
        colors={['rgba(13,10,30,0.2)', 'rgba(13,10,30,0.6)', 'rgba(13,10,30,0.98)']}
        style={StyleSheet.absoluteFillObject}
      />

      {/* Content */}
      <Animated.View
        style={[welcome.content, { opacity: fadeIn, transform: [{ translateY: slideUp }] }]}
      >
        {/* Logo badge */}
        <View style={welcome.logoBadge}>
          <Ionicons name="airplane" size={18} color={COLORS.accent} />
          <Text style={welcome.logoText}>TRAVEL ODYSSEY</Text>
        </View>

        <Text style={welcome.headline}>
          Your world.{'\n'}
          <Text style={welcome.headlineAccent}>Perfectly crafted.</Text>
        </Text>
        <Text style={welcome.subtitle}>
          Tell us where you want to go. Our expert concierge builds every detail of your perfect trip — personally, just for you.
        </Text>

        {/* Feature pills */}
        <View style={welcome.pillsRow}>
          {['✈️ Flights', '🏨 Hotels', '🍽️ Dining', '🎯 Activities'].map((pill) => (
            <View key={pill} style={welcome.pill}>
              <Text style={welcome.pillText}>{pill}</Text>
            </View>
          ))}
        </View>

        {/* CTA */}
        <TouchableOpacity style={welcome.startBtn} onPress={onStart} activeOpacity={0.88}>
          <LinearGradient
            colors={[COLORS.accent, '#E8943A']}
            start={{ x: 0, y: 0 }}
            end={{ x: 1, y: 0 }}
            style={welcome.startGradient}
          >
            <Text style={welcome.startBtnText}>Let's Get Started</Text>
            <Ionicons name="arrow-forward" size={18} color={COLORS.primary} />
          </LinearGradient>
        </TouchableOpacity>

        <TouchableOpacity onPress={onSkip} style={welcome.skipBtn}>
          <Text style={welcome.skipText}>I'll set this up later</Text>
        </TouchableOpacity>
      </Animated.View>

      {/* Bottom image indicators */}
      <View style={welcome.indicators}>
        {WELCOME_IMAGES.map((_, i) => (
          <View
            key={i}
            style={[welcome.indicator, bgIndex === i && welcome.indicatorActive]}
          />
        ))}
      </View>
    </View>
  );
};

// ── Main Onboarding Component ─────────────────────────────────────────
export const OnboardingScreen: React.FC<Props> = ({ navigation }) => {
  const [showWelcome, setShowWelcome] = useState(true);
  const [currentStep, setCurrentStep] = useState(0);
  const [selections, setSelections] = useState<Record<string, string | string[]>>({});
  const [saving, setSaving] = useState(false);

  // Slide + fade transition
  const slideAnim = useRef(new Animated.Value(0)).current;
  const fadeAnim  = useRef(new Animated.Value(1)).current;

  const { setOnboardingComplete, updatePreferences } = useStore();
  const step = STEPS[currentStep];

  const animateTransition = (direction: 'forward' | 'back', callback: () => void) => {
    const toValue = direction === 'forward' ? -width : width;
    Animated.parallel([
      Animated.timing(fadeAnim, { toValue: 0, duration: 180, useNativeDriver: true }),
      Animated.timing(slideAnim, { toValue, duration: 220, useNativeDriver: true }),
    ]).start(() => {
      callback();
      slideAnim.setValue(direction === 'forward' ? width : -width);
      Animated.parallel([
        Animated.timing(fadeAnim, { toValue: 1, duration: 250, useNativeDriver: true }),
        Animated.timing(slideAnim, { toValue: 0, duration: 280, useNativeDriver: true }),
      ]).start();
    });
  };

  const toggleSelection = (value: string) => {
    const stepId = step.id;
    if (step.multiple) {
      const current = (selections[stepId] as string[]) || [];
      if (value === 'none') {
        setSelections({ ...selections, [stepId]: ['none'] });
        return;
      }
      const withoutNone = current.filter((v) => v !== 'none');
      setSelections({
        ...selections,
        [stepId]: withoutNone.includes(value)
          ? withoutNone.filter((v) => v !== value)
          : [...withoutNone, value],
      });
    } else {
      setSelections({ ...selections, [stepId]: value });
    }
  };

  const isSelected = (value: string): boolean => {
    const sel = selections[step.id];
    if (Array.isArray(sel)) return sel.includes(value);
    return sel === value;
  };

  const canContinue = () => {
    const sel = selections[step.id];
    if (!sel) return false;
    if (Array.isArray(sel)) return sel.length > 0;
    return !!sel;
  };

  const handleBack = () => {
    if (currentStep === 0) { setShowWelcome(true); return; }
    animateTransition('back', () => setCurrentStep((s) => s - 1));
  };

  const handleNext = async () => {
    if (currentStep < STEPS.length - 1) {
      animateTransition('forward', () => setCurrentStep((s) => s + 1));
      return;
    }
    // Final step — save & proceed
    setSaving(true);
    try {
      const prefs = {
        travelStyle: selections.style as string,
        activities: selections.activities as string[],
        cuisines: selections.cuisine as string[],
        dietaryRestrictions: selections.dietary as string[],
        budgetTier: selections.budget as string,
        companions: selections.companions as string,
        pacePreference: 'moderate',
        accommodation: 'hotel',
      };
      updatePreferences(prefs);
      try { await preferencesAPI.save(prefs); } catch {}
      await setOnboardingComplete(true);
      navigation.replace('Main');
    } catch {
      Alert.alert('Error', 'Could not save preferences. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  if (showWelcome) {
    return (
      <WelcomeSlide
        onStart={() => setShowWelcome(false)}
        onSkip={async () => {
          await setOnboardingComplete(true);
          navigation.replace('Main');
        }}
      />
    );
  }

  const progress = (currentStep + 1) / STEPS.length;

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Step background image with overlay */}
      <Image
        source={{ uri: STEP_BG[currentStep] }}
        style={StyleSheet.absoluteFillObject}
        resizeMode="cover"
      />
      <LinearGradient
        colors={['rgba(13,10,30,0.6)', 'rgba(13,10,30,0.92)', 'rgba(13,10,30,1)']}
        style={StyleSheet.absoluteFillObject}
      />

      {/* ── HEADER ── */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={handleBack}>
          <Ionicons name="arrow-back" size={18} color={COLORS.white} />
        </TouchableOpacity>

        {/* Step dots */}
        <View style={styles.dotsRow}>
          {STEPS.map((_, i) => (
            <View
              key={i}
              style={[
                styles.dot,
                i === currentStep && styles.dotActive,
                i < currentStep && styles.dotDone,
              ]}
            />
          ))}
        </View>

        <TouchableOpacity
          style={styles.skipBtn}
          onPress={async () => {
            await setOnboardingComplete(true);
            navigation.replace('Main');
          }}
        >
          <Text style={styles.skipText}>Skip</Text>
        </TouchableOpacity>
      </View>

      {/* Progress bar */}
      <View style={styles.progressTrack}>
        <Animated.View style={[styles.progressFill, { width: `${progress * 100}%` }]} />
      </View>

      {/* ── STEP CONTENT ── */}
      <Animated.View
        style={[
          styles.stepWrap,
          { opacity: fadeAnim, transform: [{ translateX: slideAnim }] },
        ]}
      >
        {/* Step header */}
        <View style={styles.stepHeader}>
          <Text style={styles.stepEmoji}>{step.emoji}</Text>
          <Text style={styles.stepTitle}>{step.title}</Text>
          <Text style={styles.stepSubtitle}>{step.subtitle}</Text>
          {step.multiple && (
            <View style={styles.multiHint}>
              <Ionicons name="checkmark-done" size={12} color={COLORS.accent} />
              <Text style={styles.multiHintText}>Select all that apply</Text>
            </View>
          )}
        </View>

        {/* Options grid */}
        <ScrollView
          showsVerticalScrollIndicator={false}
          contentContainerStyle={styles.optionsContainer}
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.optionsGrid}>
            {step.options.map((option) => {
              const selected = isSelected(option.value);
              return (
                <TouchableOpacity
                  key={option.value}
                  style={[styles.option, selected && styles.optionSelected]}
                  onPress={() => toggleSelection(option.value)}
                  activeOpacity={0.8}
                >
                  {selected && (
                    <View style={styles.checkBadge}>
                      <Ionicons name="checkmark" size={10} color={COLORS.white} />
                    </View>
                  )}
                  <View style={[styles.optionIconWrap, selected && styles.optionIconSelected]}>
                    <Ionicons
                      name={option.icon}
                      size={20}
                      color={selected ? COLORS.white : COLORS.secondary}
                    />
                  </View>
                  <Text style={[styles.optionLabel, selected && styles.optionLabelSelected]}>
                    {option.label}
                  </Text>
                  {!!option.desc && (
                    <Text style={[styles.optionDesc, selected && styles.optionDescSelected]}>
                      {option.desc}
                    </Text>
                  )}
                </TouchableOpacity>
              );
            })}
          </View>
        </ScrollView>
      </Animated.View>

      {/* ── FOOTER ── */}
      <View style={styles.footer}>
        <TouchableOpacity
          style={[styles.continueBtn, !canContinue() && styles.continueBtnDisabled]}
          onPress={handleNext}
          disabled={!canContinue() || saving}
          activeOpacity={0.88}
        >
          {saving ? (
            <Text style={styles.continueBtnText}>Saving…</Text>
          ) : (
            <>
              <Text style={styles.continueBtnText}>
                {currentStep === STEPS.length - 1 ? 'Complete Setup ✦' : 'Continue'}
              </Text>
              {!saving && <Ionicons name="arrow-forward" size={18} color={COLORS.primary} />}
            </>
          )}
        </TouchableOpacity>

        <Text style={styles.footerHint}>
          Step {currentStep + 1} of {STEPS.length} — your preferences personalise every trip
        </Text>
      </View>
    </View>
  );
};

// ── Welcome styles ────────────────────────────────────────────────────
const welcome = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0D0A1E', justifyContent: 'flex-end' },
  content: { padding: SPACING.xl, paddingBottom: SPACING.xxl },
  logoBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.xs,
    backgroundColor: 'rgba(245,166,35,0.15)',
    borderWidth: 1,
    borderColor: 'rgba(245,166,35,0.4)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.xs,
    alignSelf: 'flex-start',
    marginBottom: SPACING.lg,
  },
  logoText: { color: COLORS.accent, fontSize: FONTS.sizes.xs, fontWeight: '800', letterSpacing: 1.5 },
  headline: {
    color: COLORS.white,
    fontSize: 40,
    fontWeight: '800',
    lineHeight: 48,
    marginBottom: SPACING.md,
  },
  headlineAccent: { color: COLORS.accent },
  subtitle: {
    color: 'rgba(255,255,255,0.6)',
    fontSize: FONTS.sizes.md,
    lineHeight: 24,
    marginBottom: SPACING.lg,
  },
  pillsRow: { flexDirection: 'row', flexWrap: 'wrap', gap: SPACING.sm, marginBottom: SPACING.xl },
  pill: {
    backgroundColor: 'rgba(255,255,255,0.1)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.xs,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.15)',
  },
  pillText: { color: 'rgba(255,255,255,0.8)', fontSize: FONTS.sizes.sm, fontWeight: '600' },
  startBtn: { borderRadius: RADIUS.full, overflow: 'hidden', marginBottom: SPACING.md, ...SHADOWS.lg },
  startGradient: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: SPACING.sm,
    paddingVertical: SPACING.md + 2,
  },
  startBtnText: { color: COLORS.primary, fontWeight: '800', fontSize: FONTS.sizes.lg },
  skipBtn: { alignItems: 'center', paddingVertical: SPACING.sm },
  skipText: { color: 'rgba(255,255,255,0.4)', fontSize: FONTS.sizes.sm },
  indicators: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: 6,
    position: 'absolute',
    top: SPACING.xxl + 16,
    left: 0,
    right: 0,
  },
  indicator: { width: 6, height: 6, borderRadius: 3, backgroundColor: 'rgba(255,255,255,0.3)' },
  indicatorActive: { width: 20, backgroundColor: COLORS.accent },
});

// ── Step styles ───────────────────────────────────────────────────────
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },

  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.xxl + 8,
    paddingBottom: SPACING.md,
  },
  backBtn: {
    width: 38,
    height: 38,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(255,255,255,0.12)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  dotsRow: { flexDirection: 'row', gap: 6, alignItems: 'center' },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: 'rgba(255,255,255,0.2)',
  },
  dotActive: { width: 20, backgroundColor: COLORS.accent },
  dotDone: { backgroundColor: COLORS.secondary },
  skipBtn: { paddingHorizontal: SPACING.sm, paddingVertical: SPACING.xs },
  skipText: { color: 'rgba(255,255,255,0.4)', fontSize: FONTS.sizes.sm },

  progressTrack: {
    height: 2,
    backgroundColor: 'rgba(255,255,255,0.1)',
    marginHorizontal: SPACING.lg,
    borderRadius: RADIUS.full,
    marginBottom: SPACING.lg,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: COLORS.accent,
    borderRadius: RADIUS.full,
  },

  stepWrap: { flex: 1 },

  stepHeader: { paddingHorizontal: SPACING.lg, marginBottom: SPACING.lg },
  stepEmoji: { fontSize: 36, marginBottom: SPACING.sm },
  stepTitle: {
    color: COLORS.white,
    fontSize: FONTS.sizes.xxl,
    fontWeight: '800',
    marginBottom: SPACING.xs,
  },
  stepSubtitle: {
    color: 'rgba(255,255,255,0.6)',
    fontSize: FONTS.sizes.md,
    lineHeight: 22,
    marginBottom: SPACING.xs,
  },
  multiHint: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
    marginTop: SPACING.sm,
  },
  multiHintText: { color: COLORS.accent, fontSize: FONTS.sizes.xs, fontWeight: '600' },

  optionsContainer: { paddingHorizontal: SPACING.lg, paddingBottom: SPACING.lg },
  optionsGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: SPACING.sm },

  option: {
    width: (width - SPACING.lg * 2 - SPACING.sm) / 2,
    backgroundColor: 'rgba(255,255,255,0.07)',
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    borderWidth: 1.5,
    borderColor: 'rgba(255,255,255,0.1)',
    position: 'relative',
  },
  optionSelected: {
    backgroundColor: 'rgba(108,60,225,0.25)',
    borderColor: COLORS.secondary,
  },
  checkBadge: {
    position: 'absolute',
    top: SPACING.sm,
    right: SPACING.sm,
    width: 18,
    height: 18,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.secondary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  optionIconWrap: {
    width: 42,
    height: 42,
    borderRadius: RADIUS.md,
    backgroundColor: 'rgba(108,60,225,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: SPACING.sm,
  },
  optionIconSelected: { backgroundColor: COLORS.secondary },
  optionLabel: {
    color: 'rgba(255,255,255,0.85)',
    fontSize: FONTS.sizes.md,
    fontWeight: '700',
    marginBottom: 2,
  },
  optionLabelSelected: { color: COLORS.white },
  optionDesc: { color: 'rgba(255,255,255,0.4)', fontSize: FONTS.sizes.xs },
  optionDescSelected: { color: 'rgba(255,255,255,0.6)' },

  footer: {
    paddingHorizontal: SPACING.lg,
    paddingBottom: SPACING.xxl,
    paddingTop: SPACING.md,
    backgroundColor: 'rgba(13,10,30,0.95)',
  },
  continueBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: SPACING.sm,
    backgroundColor: COLORS.accent,
    borderRadius: RADIUS.full,
    paddingVertical: SPACING.md + 2,
    marginBottom: SPACING.sm,
    ...SHADOWS.md,
  },
  continueBtnDisabled: { opacity: 0.35 },
  continueBtnText: { color: COLORS.primary, fontWeight: '800', fontSize: FONTS.sizes.md },
  footerHint: {
    color: 'rgba(255,255,255,0.3)',
    fontSize: FONTS.sizes.xs,
    textAlign: 'center',
  },
});
