import React, { useState, useRef } from 'react';
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
} from 'react-native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { Ionicons } from '@expo/vector-icons';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { preferencesAPI } from '../../services/api';

const { width } = Dimensions.get('window');

type Props = {
  navigation: NativeStackNavigationProp<RootStackParamList, 'Onboarding'>;
};

const STEPS = [
  {
    id: 'style',
    title: 'Your Travel Style',
    subtitle: 'How do you like to explore?',
    emoji: '🌍',
    options: [
      { value: 'adventure', label: 'Adventure', icon: 'bicycle', desc: 'Hiking, sports & thrills' },
      { value: 'relaxed', label: 'Relaxed', icon: 'sunny', desc: 'Beaches, spas & slow days' },
      { value: 'cultural', label: 'Cultural', icon: 'library', desc: 'Museums, history & art' },
      { value: 'foodie', label: 'Foodie', icon: 'restaurant', desc: 'Local cuisine & fine dining' },
      { value: 'luxury', label: 'Luxury', icon: 'diamond', desc: 'Premium & exclusive experiences' },
      { value: 'budget', label: 'Smart Saver', icon: 'wallet', desc: 'Best value for money' },
    ],
    multiple: false,
  },
  {
    id: 'activities',
    title: 'Favorite Activities',
    subtitle: 'Pick everything you enjoy',
    emoji: '🎯',
    options: [
      { value: 'museums', label: 'Museums', icon: 'business', desc: '' },
      { value: 'beaches', label: 'Beaches', icon: 'water', desc: '' },
      { value: 'hiking', label: 'Hiking', icon: 'walk', desc: '' },
      { value: 'nightlife', label: 'Nightlife', icon: 'moon', desc: '' },
      { value: 'shopping', label: 'Shopping', icon: 'bag-handle', desc: '' },
      { value: 'cooking', label: 'Cooking Classes', icon: 'flame', desc: '' },
      { value: 'sports', label: 'Sports', icon: 'football', desc: '' },
      { value: 'photography', label: 'Photography', icon: 'camera', desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'cuisine',
    title: 'Food Preferences',
    subtitle: 'What cuisine excites you?',
    emoji: '🍽️',
    options: [
      { value: 'italian', label: 'Italian', icon: 'pizza', desc: '' },
      { value: 'asian', label: 'Asian', icon: 'fish', desc: '' },
      { value: 'mediterranean', label: 'Mediterranean', icon: 'leaf', desc: '' },
      { value: 'american', label: 'American', icon: 'fast-food', desc: '' },
      { value: 'french', label: 'French', icon: 'wine', desc: '' },
      { value: 'middle-eastern', label: 'Middle Eastern', icon: 'cafe', desc: '' },
      { value: 'indian', label: 'Indian', icon: 'color-fill', desc: '' },
      { value: 'local', label: 'Always Local', icon: 'location', desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'dietary',
    title: 'Dietary Needs',
    subtitle: 'Any dietary restrictions?',
    emoji: '🥗',
    options: [
      { value: 'none', label: 'No restrictions', icon: 'checkmark-circle', desc: '' },
      { value: 'vegetarian', label: 'Vegetarian', icon: 'leaf', desc: '' },
      { value: 'vegan', label: 'Vegan', icon: 'nutrition', desc: '' },
      { value: 'gluten-free', label: 'Gluten Free', icon: 'ban', desc: '' },
      { value: 'halal', label: 'Halal', icon: 'shield-checkmark', desc: '' },
      { value: 'kosher', label: 'Kosher', icon: 'star', desc: '' },
    ],
    multiple: true,
  },
  {
    id: 'budget',
    title: 'Budget Tier',
    subtitle: 'What\'s your typical travel budget?',
    emoji: '💰',
    options: [
      { value: 'budget', label: 'Budget', icon: 'trending-down', desc: 'Under €1,500/week' },
      { value: 'moderate', label: 'Moderate', icon: 'trending-up', desc: '€1,500 – €3,000/week' },
      { value: 'premium', label: 'Premium', icon: 'star', desc: '€3,000 – €6,000/week' },
      { value: 'luxury', label: 'Luxury', icon: 'diamond', desc: '€6,000+/week' },
    ],
    multiple: false,
  },
  {
    id: 'companions',
    title: 'Travel With',
    subtitle: 'Who do you usually travel with?',
    emoji: '👥',
    options: [
      { value: 'solo', label: 'Solo', icon: 'person', desc: 'Just me, myself & I' },
      { value: 'partner', label: 'Partner', icon: 'heart', desc: 'Romantic getaways' },
      { value: 'friends', label: 'Friends', icon: 'people', desc: 'Squad adventures' },
      { value: 'family', label: 'Family', icon: 'home', desc: 'Kid-friendly trips' },
    ],
    multiple: false,
  },
];

export const OnboardingScreen: React.FC<Props> = ({ navigation }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [selections, setSelections] = useState<Record<string, string | string[]>>({});
  const [saving, setSaving] = useState(false);
  const progressAnim = useRef(new Animated.Value(0)).current;
  const { setOnboardingComplete, updatePreferences } = useStore();

  const step = STEPS[currentStep];
  const progress = (currentStep + 1) / STEPS.length;

  Animated.timing(progressAnim, {
    toValue: progress,
    duration: 300,
    useNativeDriver: false,
  }).start();

  const toggleSelection = (value: string) => {
    const stepId = step.id;
    if (step.multiple) {
      const current = (selections[stepId] as string[]) || [];
      if (value === 'none') {
        setSelections({ ...selections, [stepId]: ['none'] });
        return;
      }
      const withoutNone = current.filter((v) => v !== 'none');
      if (withoutNone.includes(value)) {
        setSelections({ ...selections, [stepId]: withoutNone.filter((v) => v !== value) });
      } else {
        setSelections({ ...selections, [stepId]: [...withoutNone, value] });
      }
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

  const handleNext = async () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
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
        try {
          await preferencesAPI.save(prefs);
        } catch {}
        await setOnboardingComplete(true);
        navigation.replace('Main');
      } catch (e) {
        Alert.alert('Error', 'Could not save preferences. Please try again.');
      } finally {
        setSaving(false);
      }
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerTop}>
          {currentStep > 0 ? (
            <TouchableOpacity
              style={styles.backBtn}
              onPress={() => setCurrentStep(currentStep - 1)}
            >
              <Ionicons name="arrow-back" size={20} color={COLORS.text} />
            </TouchableOpacity>
          ) : (
            <View style={{ width: 38 }} />
          )}
          <Text style={styles.stepCount}>
            {currentStep + 1} / {STEPS.length}
          </Text>
          <TouchableOpacity onPress={() => navigation.replace('Main')}>
            <Text style={styles.skipText}>Skip</Text>
          </TouchableOpacity>
        </View>

        {/* Progress Bar */}
        <View style={styles.progressBar}>
          <Animated.View
            style={[
              styles.progressFill,
              {
                width: progressAnim.interpolate({
                  inputRange: [0, 1],
                  outputRange: ['0%', '100%'],
                }),
              },
            ]}
          />
        </View>
      </View>

      {/* Step Content */}
      <ScrollView
        style={styles.content}
        contentContainerStyle={styles.contentContainer}
        showsVerticalScrollIndicator={false}
      >
        <Text style={styles.emoji}>{step.emoji}</Text>
        <Text style={styles.title}>{step.title}</Text>
        <Text style={styles.subtitle}>{step.subtitle}</Text>

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
                <View style={[styles.optionIcon, selected && styles.optionIconSelected]}>
                  <Ionicons
                    name={option.icon as any}
                    size={22}
                    color={selected ? COLORS.white : COLORS.textSecondary}
                  />
                </View>
                <Text style={[styles.optionLabel, selected && styles.optionLabelSelected]}>
                  {option.label}
                </Text>
                {option.desc ? (
                  <Text style={styles.optionDesc}>{option.desc}</Text>
                ) : null}
                {selected && (
                  <View style={styles.checkmark}>
                    <Ionicons name="checkmark" size={12} color={COLORS.white} />
                  </View>
                )}
              </TouchableOpacity>
            );
          })}
        </View>
      </ScrollView>

      {/* Footer */}
      <View style={styles.footer}>
        <Button
          label={currentStep === STEPS.length - 1 ? 'Complete Setup' : 'Continue'}
          onPress={handleNext}
          disabled={!canContinue()}
          loading={saving}
        />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.background,
  },
  header: {
    paddingTop: SPACING.xxl,
    paddingHorizontal: SPACING.lg,
    paddingBottom: SPACING.md,
  },
  headerTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: SPACING.md,
  },
  backBtn: {
    width: 38,
    height: 38,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  stepCount: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
    fontWeight: '600',
  },
  skipText: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.sm,
    fontWeight: '600',
  },
  progressBar: {
    height: 4,
    backgroundColor: COLORS.border,
    borderRadius: RADIUS.full,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: COLORS.secondary,
    borderRadius: RADIUS.full,
  },
  content: {
    flex: 1,
  },
  contentContainer: {
    padding: SPACING.lg,
    paddingTop: SPACING.xl,
  },
  emoji: {
    fontSize: 48,
    marginBottom: SPACING.md,
  },
  title: {
    color: COLORS.text,
    fontSize: FONTS.sizes.xxl,
    fontWeight: '800',
    marginBottom: SPACING.xs,
  },
  subtitle: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.md,
    marginBottom: SPACING.xl,
  },
  optionsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: SPACING.sm,
  },
  option: {
    width: (width - SPACING.lg * 2 - SPACING.sm) / 2,
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    borderWidth: 1.5,
    borderColor: COLORS.border,
    position: 'relative',
  },
  optionSelected: {
    backgroundColor: 'rgba(108,60,225,0.15)',
    borderColor: COLORS.secondary,
  },
  optionIcon: {
    width: 42,
    height: 42,
    borderRadius: RADIUS.md,
    backgroundColor: COLORS.surfaceLight,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: SPACING.sm,
  },
  optionIconSelected: {
    backgroundColor: COLORS.secondary,
  },
  optionLabel: {
    color: COLORS.text,
    fontSize: FONTS.sizes.md,
    fontWeight: '600',
  },
  optionLabelSelected: {
    color: COLORS.white,
  },
  optionDesc: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.xs,
    marginTop: 2,
  },
  checkmark: {
    position: 'absolute',
    top: SPACING.sm,
    right: SPACING.sm,
    width: 20,
    height: 20,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.secondary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  footer: {
    padding: SPACING.lg,
    paddingBottom: SPACING.xxl,
  },
});
