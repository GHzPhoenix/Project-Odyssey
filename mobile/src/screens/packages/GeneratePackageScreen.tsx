import React, { useState, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  TextInput,
  Animated,
  Alert,
  StatusBar,
  ActivityIndicator,
  Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI } from '../../services/api';

const { width } = Dimensions.get('window');

const POPULAR_DESTINATIONS = [
  { name: 'London',        emoji: '🇬🇧' },
  { name: 'Paris',         emoji: '🇫🇷' },
  { name: 'Tokyo',         emoji: '🇯🇵' },
  { name: 'Dubai',         emoji: '🇦🇪' },
  { name: 'Barcelona',     emoji: '🇪🇸' },
  { name: 'Rome',          emoji: '🇮🇹' },
  { name: 'Bali',          emoji: '🇮🇩' },
  { name: 'New York',      emoji: '🇺🇸' },
  { name: 'Sydney',        emoji: '🇦🇺' },
  { name: 'Santorini',     emoji: '🇬🇷' },
  { name: 'Maldives',      emoji: '🇲🇻' },
  { name: 'Amsterdam',     emoji: '🇳🇱' },
  { name: 'Lisbon',        emoji: '🇵🇹' },
  { name: 'Prague',        emoji: '🇨🇿' },
  { name: 'Vienna',        emoji: '🇦🇹' },
  { name: 'Kyoto',         emoji: '🇯🇵' },
  { name: 'Bangkok',       emoji: '🇹🇭' },
  { name: 'Singapore',     emoji: '🇸🇬' },
  { name: 'Marrakech',     emoji: '🇲🇦' },
  { name: 'Amalfi Coast',  emoji: '🇮🇹' },
  { name: 'Istanbul',      emoji: '🇹🇷' },
  { name: 'Mykonos',       emoji: '🇬🇷' },
  { name: 'Cappadocia',    emoji: '🇹🇷' },
  { name: 'Maldives',      emoji: '🇲🇻' },
  { name: 'Phuket',        emoji: '🇹🇭' },
  { name: 'Cape Town',     emoji: '🇿🇦' },
  { name: 'New Zealand',   emoji: '🇳🇿' },
  { name: 'Venice',        emoji: '🇮🇹' },
  { name: 'Budapest',      emoji: '🇭🇺' },
  { name: 'Dubrovnik',     emoji: '🇭🇷' },
];

const DEPARTURE_CITIES = [
  'Athens', 'Thessaloniki', 'London', 'Paris', 'Amsterdam', 'Berlin', 'Frankfurt',
  'Rome', 'Milan', 'Madrid', 'Barcelona', 'Lisbon', 'Vienna', 'Zurich', 'Brussels',
  'Stockholm', 'Copenhagen', 'Dublin', 'Warsaw', 'Budapest', 'Bucharest',
];

// Converts DD/MM/YYYY → YYYY-MM-DD for the API
const parseEuroDate = (input: string): string | null => {
  const parts = input.split('/');
  if (parts.length !== 3) return null;
  const [dd, mm, yyyy] = parts;
  if (dd.length !== 2 || mm.length !== 2 || yyyy.length !== 4) return null;
  const iso = `${yyyy}-${mm}-${dd}`;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return iso;
};

// Auto-inserts slashes as user types: 20121995 → 20/12/1995
const formatDateInput = (text: string, prev: string): string => {
  const digits = text.replace(/\D/g, '').slice(0, 8);
  if (digits.length <= 2) return digits;
  if (digits.length <= 4) return `${digits.slice(0, 2)}/${digits.slice(2)}`;
  return `${digits.slice(0, 2)}/${digits.slice(2, 4)}/${digits.slice(4)}`;
};

export const GeneratePackageScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { user } = useStore();
  const [destination, setDestination]         = useState('');
  const [departureLocation, setDepartureLocation] = useState('');
  const [startDate, setStartDate]             = useState('');
  const [duration, setDuration]               = useState(7);
  const [guests, setGuests]                   = useState(2);
  const [generating, setGenerating]           = useState(false);
  const [showDestSuggestions, setShowDestSuggestions] = useState(false);
  const [showDepSuggestions, setShowDepSuggestions]   = useState(false);

  const pulseAnim = useRef(new Animated.Value(1)).current;

  const filteredDests = POPULAR_DESTINATIONS.filter((d) =>
    d.name.toLowerCase().includes(destination.toLowerCase())
  );
  const filteredDep = DEPARTURE_CITIES.filter((c) =>
    c.toLowerCase().includes(departureLocation.toLowerCase())
  );

  const startPulse = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, { toValue: 1.05, duration: 600, useNativeDriver: true }),
        Animated.timing(pulseAnim, { toValue: 1, duration: 600, useNativeDriver: true }),
      ])
    ).start();
  };

  const handleGenerate = async () => {
    if (!destination.trim()) {
      Alert.alert('Missing Destination', 'Please enter or select a destination.');
      return;
    }
    if (!startDate.trim()) {
      Alert.alert('Missing Date', 'Please enter your departure date.');
      return;
    }
    const isoStart = parseEuroDate(startDate);
    if (!isoStart) {
      Alert.alert('Invalid Date', 'Please enter the date in DD/MM/YYYY format (e.g. 20/12/2025).');
      return;
    }
    if (duration < 3) {
      Alert.alert('Minimum Duration', 'Trip duration must be at least 3 days.');
      return;
    }

    setGenerating(true);
    startPulse();

    const endDateObj = new Date(isoStart);
    endDateObj.setDate(endDateObj.getDate() + duration);
    const endDate = endDateObj.toISOString().split('T')[0];

    try {
      await packagesAPI.generate({
        destination,
        startDate: isoStart,
        endDate,
        guests,
        departureLocation: departureLocation.trim() || undefined,
      });
      pulseAnim.stopAnimation();
      Alert.alert(
        '✈️ Request Received!',
        `Your ${duration}-day trip to ${destination} has been submitted.\n\nOur travel experts will craft your personalised package and contact you within 24 hours.`,
        [{ text: 'Back to Home', onPress: () => navigation.navigate('Main') }]
      );
    } catch (err: any) {
      pulseAnim.stopAnimation();
      const msg = err?.response?.data?.error || 'Could not submit request. Please check your connection and try again.';
      Alert.alert('Request Failed', msg);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Request a Trip</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView style={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Preferences Summary */}
        {user?.preferences && (
          <View style={styles.prefSummary}>
            <Ionicons name="person-circle-outline" size={16} color={COLORS.accent} />
            <Text style={styles.prefText}>
              Your preferences are saved — our experts will tailor your trip accordingly.
            </Text>
          </View>
        )}

        {/* Destination Input */}
        <View style={styles.section}>
          <Text style={styles.label}>Where to?</Text>
          <View style={styles.searchContainer}>
            <Ionicons name="location-outline" size={20} color={COLORS.secondary} style={styles.searchIcon} />
            <TextInput
              style={styles.searchInput}
              placeholder="Search destinations..."
              placeholderTextColor={COLORS.textMuted}
              value={destination}
              onChangeText={(t) => {
                setDestination(t);
                setShowDestSuggestions(t.length > 0);
              }}
              onFocus={() => setShowDestSuggestions(destination.length > 0 || true)}
            />
            {destination ? (
              <TouchableOpacity onPress={() => { setDestination(''); setShowDestSuggestions(false); }}>
                <Ionicons name="close-circle" size={18} color={COLORS.textMuted} />
              </TouchableOpacity>
            ) : null}
          </View>

          {/* Destination Suggestions */}
          {showDestSuggestions && (
            <View style={styles.suggestions}>
              {(destination ? filteredDests : POPULAR_DESTINATIONS).slice(0, 6).map((d) => (
                <TouchableOpacity
                  key={d.name}
                  style={styles.suggestionItem}
                  onPress={() => {
                    setDestination(d.name);
                    setShowDestSuggestions(false);
                  }}
                >
                  <Text style={styles.suggestionEmoji}>{d.emoji}</Text>
                  <Text style={styles.suggestionName}>{d.name}</Text>
                  <Ionicons name="chevron-forward" size={14} color={COLORS.textMuted} />
                </TouchableOpacity>
              ))}
            </View>
          )}
        </View>

        {/* Departure City */}
        <View style={styles.section}>
          <Text style={styles.label}>Flying From (optional)</Text>
          <View style={styles.searchContainer}>
            <Ionicons name="airplane-outline" size={20} color={COLORS.secondary} style={styles.searchIcon} />
            <TextInput
              style={styles.searchInput}
              placeholder="e.g. Athens, London..."
              placeholderTextColor={COLORS.textMuted}
              value={departureLocation}
              onChangeText={(t) => {
                setDepartureLocation(t);
                setShowDepSuggestions(t.length > 0);
              }}
              onFocus={() => setShowDepSuggestions(departureLocation.length > 0 || true)}
            />
            {departureLocation ? (
              <TouchableOpacity onPress={() => { setDepartureLocation(''); setShowDepSuggestions(false); }}>
                <Ionicons name="close-circle" size={18} color={COLORS.textMuted} />
              </TouchableOpacity>
            ) : null}
          </View>
          {showDepSuggestions && (
            <View style={styles.suggestions}>
              {(departureLocation ? filteredDep : DEPARTURE_CITIES).slice(0, 5).map((city) => (
                <TouchableOpacity
                  key={city}
                  style={styles.suggestionItem}
                  onPress={() => {
                    setDepartureLocation(city);
                    setShowDepSuggestions(false);
                  }}
                >
                  <Ionicons name="airplane-outline" size={16} color={COLORS.textMuted} />
                  <Text style={styles.suggestionName}>{city}</Text>
                  <Ionicons name="chevron-forward" size={14} color={COLORS.textMuted} />
                </TouchableOpacity>
              ))}
            </View>
          )}
        </View>

        {/* Start Date */}
        <View style={styles.section}>
          <Text style={styles.label}>Departure Date</Text>
          <View style={styles.inputRow}>
            <Ionicons name="calendar-outline" size={20} color={COLORS.secondary} style={styles.searchIcon} />
            <TextInput
              style={styles.searchInput}
              placeholder="DD/MM/YYYY (e.g. 20/12/2025)"
              placeholderTextColor={COLORS.textMuted}
              value={startDate}
              onChangeText={(text) => setStartDate(formatDateInput(text, startDate))}
              keyboardType="number-pad"
              maxLength={10}
            />
          </View>
        </View>

        {/* Duration */}
        <View style={styles.section}>
          <Text style={styles.label}>Duration (days · min. 3)</Text>
          <View style={styles.guestRow}>
            <TouchableOpacity
              style={[styles.guestBtn, duration <= 3 && styles.guestBtnDisabled]}
              onPress={() => setDuration(Math.max(3, duration - 1))}
            >
              <Ionicons name="remove" size={20} color={duration <= 3 ? COLORS.textMuted : COLORS.text} />
            </TouchableOpacity>
            <View style={styles.guestCount}>
              <Text style={styles.guestNumber}>{duration}</Text>
              <Text style={styles.guestLabel}>{duration === 1 ? 'Day' : 'Days'}</Text>
            </View>
            <TouchableOpacity
              style={styles.guestBtn}
              onPress={() => setDuration(duration + 1)}
            >
              <Ionicons name="add" size={20} color={COLORS.text} />
            </TouchableOpacity>
          </View>
        </View>

        {/* Guests */}
        <View style={styles.section}>
          <Text style={styles.label}>Guests</Text>
          <View style={styles.guestRow}>
            <TouchableOpacity
              style={styles.guestBtn}
              onPress={() => setGuests(Math.max(1, guests - 1))}
            >
              <Ionicons name="remove" size={20} color={COLORS.text} />
            </TouchableOpacity>
            <View style={styles.guestCount}>
              <Text style={styles.guestNumber}>{guests}</Text>
              <Text style={styles.guestLabel}>{guests === 1 ? 'Guest' : 'Guests'}</Text>
            </View>
            <TouchableOpacity
              style={styles.guestBtn}
              onPress={() => setGuests(Math.min(10, guests + 1))}
            >
              <Ionicons name="add" size={20} color={COLORS.text} />
            </TouchableOpacity>
          </View>
        </View>

        {/* What's Included */}
        <View style={styles.includedSection}>
          <Text style={styles.label}>What's Included</Text>
          <View style={styles.includedGrid}>
            {[
              { icon: 'airplane', label: 'Flights' },
              { icon: 'bed', label: 'Hotel' },
              { icon: 'restaurant', label: 'Restaurants' },
              { icon: 'ticket', label: 'Experiences' },
            ].map((item) => (
              <View key={item.label} style={styles.includedItem}>
                <View style={styles.includedIcon}>
                  <Ionicons name={item.icon as any} size={18} color={COLORS.secondary} />
                </View>
                <Text style={styles.includedLabel}>{item.label}</Text>
              </View>
            ))}
          </View>
        </View>

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>

      {/* Generate Button */}
      <View style={styles.footer}>
        {generating ? (
          <View style={styles.generatingContainer}>
            <Animated.View style={[styles.generatingBadge, { transform: [{ scale: pulseAnim }] }]}>
              <Ionicons name="sparkles" size={20} color={COLORS.accent} />
            </Animated.View>
            <View>
              <Text style={styles.generatingTitle}>Submitting your request...</Text>
              <Text style={styles.generatingSubtitle}>Sending to our travel experts</Text>
            </View>
            <ActivityIndicator color={COLORS.secondary} size="small" />
          </View>
        ) : (
          <Button
            label="✦  Request My Package"
            onPress={handleGenerate}
          />
        )}
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
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.xxl,
    paddingBottom: SPACING.md,
  },
  backBtn: {
    width: 38,
    height: 38,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  headerTitle: {
    color: COLORS.text,
    fontSize: FONTS.sizes.lg,
    fontWeight: '700',
  },
  scroll: {
    flex: 1,
  },
  prefSummary: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.sm,
    marginHorizontal: SPACING.lg,
    marginBottom: SPACING.lg,
    backgroundColor: 'rgba(108,60,225,0.15)',
    borderRadius: RADIUS.md,
    padding: SPACING.sm,
    borderWidth: 1,
    borderColor: 'rgba(108,60,225,0.3)',
  },
  prefText: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
    flex: 1,
  },
  section: {
    paddingHorizontal: SPACING.lg,
    marginBottom: SPACING.lg,
  },
  label: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
    fontWeight: '600',
    letterSpacing: 0.5,
    marginBottom: SPACING.sm,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.sm + 2,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.sm + 2,
  },
  searchIcon: {
    marginRight: SPACING.sm,
  },
  searchInput: {
    flex: 1,
    color: COLORS.text,
    fontSize: FONTS.sizes.md,
  },
  suggestions: {
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginTop: SPACING.xs,
    overflow: 'hidden',
  },
  suggestionItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
    gap: SPACING.md,
  },
  suggestionEmoji: {
    fontSize: 20,
  },
  suggestionName: {
    flex: 1,
    color: COLORS.text,
    fontSize: FONTS.sizes.md,
    fontWeight: '500',
  },
  durationGrid: {
    flexDirection: 'row',
    gap: SPACING.sm,
    flexWrap: 'wrap',
  },
  durationChip: {
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.sm,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    borderColor: COLORS.border,
    minWidth: 52,
    alignItems: 'center',
  },
  durationChipSelected: {
    backgroundColor: COLORS.secondary,
    borderColor: COLORS.secondary,
  },
  durationText: {
    color: COLORS.textSecondary,
    fontWeight: '600',
    fontSize: FONTS.sizes.sm,
  },
  durationTextSelected: {
    color: COLORS.white,
  },
  guestRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.xl,
  },
  guestBtn: {
    width: 44,
    height: 44,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    borderColor: COLORS.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  guestBtnDisabled: {
    opacity: 0.4,
  },
  guestCount: {
    alignItems: 'center',
  },
  guestNumber: {
    color: COLORS.text,
    fontSize: FONTS.sizes.xxl,
    fontWeight: '800',
  },
  guestLabel: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.xs,
  },
  includedSection: {
    paddingHorizontal: SPACING.lg,
    marginBottom: SPACING.lg,
  },
  includedGrid: {
    flexDirection: 'row',
    gap: SPACING.sm,
  },
  includedItem: {
    flex: 1,
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    alignItems: 'center',
    gap: SPACING.sm,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  includedIcon: {
    width: 40,
    height: 40,
    borderRadius: RADIUS.md,
    backgroundColor: 'rgba(108,60,225,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  includedLabel: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.xs,
    fontWeight: '600',
    textAlign: 'center',
  },
  footer: {
    padding: SPACING.lg,
    paddingBottom: SPACING.xxl,
    backgroundColor: COLORS.background,
  },
  generatingContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl,
    padding: SPACING.md,
    gap: SPACING.md,
    borderWidth: 1,
    borderColor: 'rgba(108,60,225,0.3)',
  },
  generatingBadge: {
    width: 44,
    height: 44,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(108,60,225,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  generatingTitle: {
    color: COLORS.text,
    fontWeight: '700',
    fontSize: FONTS.sizes.md,
  },
  generatingSubtitle: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.xs,
  },
});
