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
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI } from '../../services/api';

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

// Auto-inserts slashes as user types: 20122025 → 20/12/2025
const formatDateInput = (text: string): string => {
  const digits = text.replace(/\D/g, '').slice(0, 8);
  if (digits.length <= 2) return digits;
  if (digits.length <= 4) return `${digits.slice(0, 2)}/${digits.slice(2)}`;
  return `${digits.slice(0, 2)}/${digits.slice(2, 4)}/${digits.slice(4)}`;
};

// Simple labelled input row
const Field = ({
  icon,
  label,
  placeholder,
  value,
  onChangeText,
  keyboardType,
  maxLength,
  autoCapitalize,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  placeholder: string;
  value: string;
  onChangeText: (t: string) => void;
  keyboardType?: 'default' | 'number-pad';
  maxLength?: number;
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
}) => (
  <View style={styles.section}>
    <Text style={styles.label}>{label}</Text>
    <View style={styles.inputRow}>
      <Ionicons name={icon} size={20} color={COLORS.secondary} style={styles.inputIcon} />
      <TextInput
        style={styles.input}
        placeholder={placeholder}
        placeholderTextColor={COLORS.textMuted}
        value={value}
        onChangeText={onChangeText}
        keyboardType={keyboardType || 'default'}
        maxLength={maxLength}
        autoCapitalize={autoCapitalize || 'words'}
        returnKeyType="next"
      />
    </View>
  </View>
);

export const GeneratePackageScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { user } = useStore();
  const [destination, setDestination]         = useState('');
  const [departureLocation, setDepartureLocation] = useState('');
  const [startDate, setStartDate]             = useState('');
  const [duration, setDuration]               = useState(7);
  const [guests, setGuests]                   = useState(2);
  const [generating, setGenerating]           = useState(false);

  const pulseAnim = useRef(new Animated.Value(1)).current;

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
      Alert.alert('Missing Destination', 'Please enter your destination.');
      return;
    }
    if (!departureLocation.trim()) {
      Alert.alert('Missing Departure City', 'Please enter the city you are flying from.');
      return;
    }
    if (!startDate.trim()) {
      Alert.alert('Missing Date', 'Please enter your departure date (DD/MM/YYYY).');
      return;
    }
    const isoStart = parseEuroDate(startDate);
    if (!isoStart) {
      Alert.alert('Invalid Date', 'Please enter the date in DD/MM/YYYY format, e.g. 20/12/2025.');
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
        destination: destination.trim(),
        startDate:   isoStart,
        endDate,
        guests,
        departureLocation: departureLocation.trim(),
      });
      pulseAnim.stopAnimation();
      Alert.alert(
        '✈️ Request Received!',
        `Your ${duration}-day trip to ${destination.trim()} has been submitted.\n\nOur travel experts will craft your personalised package and contact you within 24 hours.`,
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

      <ScrollView style={styles.scroll} showsVerticalScrollIndicator={false} keyboardShouldPersistTaps="handled">
        {/* Preferences hint */}
        {user?.preferences && (
          <View style={styles.prefSummary}>
            <Ionicons name="person-circle-outline" size={16} color={COLORS.accent} />
            <Text style={styles.prefText}>
              Your preferences are saved — our experts will tailor your trip accordingly.
            </Text>
          </View>
        )}

        {/* Destination */}
        <Field
          icon="location-outline"
          label="Where to? *"
          placeholder="e.g. Santorini, Bali, Tokyo..."
          value={destination}
          onChangeText={setDestination}
        />

        {/* Flying from */}
        <Field
          icon="airplane-outline"
          label="Flying From *"
          placeholder="e.g. Athens, London, Amsterdam..."
          value={departureLocation}
          onChangeText={setDepartureLocation}
        />

        {/* Departure Date */}
        <Field
          icon="calendar-outline"
          label="Departure Date *"
          placeholder="DD/MM/YYYY"
          value={startDate}
          onChangeText={(t) => setStartDate(formatDateInput(t))}
          keyboardType="number-pad"
          maxLength={10}
          autoCapitalize="none"
        />

        {/* Duration stepper */}
        <View style={styles.section}>
          <Text style={styles.label}>Duration (days · min. 3)</Text>
          <View style={styles.stepperRow}>
            <TouchableOpacity
              style={[styles.stepperBtn, duration <= 3 && styles.stepperBtnDisabled]}
              onPress={() => setDuration(Math.max(3, duration - 1))}
            >
              <Ionicons name="remove" size={20} color={duration <= 3 ? COLORS.textMuted : COLORS.text} />
            </TouchableOpacity>
            <View style={styles.stepperValue}>
              <Text style={styles.stepperNumber}>{duration}</Text>
              <Text style={styles.stepperUnit}>{duration === 1 ? 'Day' : 'Days'}</Text>
            </View>
            <TouchableOpacity style={styles.stepperBtn} onPress={() => setDuration(duration + 1)}>
              <Ionicons name="add" size={20} color={COLORS.text} />
            </TouchableOpacity>
          </View>
        </View>

        {/* Guests stepper */}
        <View style={styles.section}>
          <Text style={styles.label}>Guests</Text>
          <View style={styles.stepperRow}>
            <TouchableOpacity
              style={styles.stepperBtn}
              onPress={() => setGuests(Math.max(1, guests - 1))}
            >
              <Ionicons name="remove" size={20} color={COLORS.text} />
            </TouchableOpacity>
            <View style={styles.stepperValue}>
              <Text style={styles.stepperNumber}>{guests}</Text>
              <Text style={styles.stepperUnit}>{guests === 1 ? 'Guest' : 'Guests'}</Text>
            </View>
            <TouchableOpacity style={styles.stepperBtn} onPress={() => setGuests(Math.min(20, guests + 1))}>
              <Ionicons name="add" size={20} color={COLORS.text} />
            </TouchableOpacity>
          </View>
        </View>

        {/* What's Included */}
        <View style={styles.includedSection}>
          <Text style={styles.label}>What's Included</Text>
          <View style={styles.includedGrid}>
            {[
              { icon: 'airplane',    label: 'Flights'      },
              { icon: 'bed',         label: 'Hotel'        },
              { icon: 'restaurant',  label: 'Restaurants'  },
              { icon: 'ticket',      label: 'Experiences'  },
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

      {/* Submit Button */}
      <View style={styles.footer}>
        {generating ? (
          <View style={styles.submittingContainer}>
            <Animated.View style={[styles.submittingIcon, { transform: [{ scale: pulseAnim }] }]}>
              <Ionicons name="paper-plane-outline" size={20} color={COLORS.accent} />
            </Animated.View>
            <View style={{ flex: 1 }}>
              <Text style={styles.submittingTitle}>Submitting your request…</Text>
              <Text style={styles.submittingSubtitle}>Sending to our travel experts</Text>
            </View>
            <ActivityIndicator color={COLORS.secondary} size="small" />
          </View>
        ) : (
          <Button label="✦  Request My Package" onPress={handleGenerate} />
        )}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container:    { flex: 1, backgroundColor: COLORS.background },
  header: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md,
  },
  backBtn: {
    width: 38, height: 38, borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface, alignItems: 'center', justifyContent: 'center',
  },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  scroll:       { flex: 1 },

  prefSummary: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.sm,
    marginHorizontal: SPACING.lg, marginBottom: SPACING.lg,
    backgroundColor: 'rgba(108,60,225,0.12)', borderRadius: RADIUS.md,
    padding: SPACING.sm, borderWidth: 1, borderColor: 'rgba(108,60,225,0.25)',
  },
  prefText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, flex: 1 },

  section:  { paddingHorizontal: SPACING.lg, marginBottom: SPACING.lg },
  label: {
    color: COLORS.textSecondary, fontSize: FONTS.sizes.sm,
    fontWeight: '600', letterSpacing: 0.5, marginBottom: SPACING.sm,
  },
  inputRow: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: COLORS.surface, borderRadius: RADIUS.md,
    borderWidth: 1, borderColor: COLORS.border,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm + 2,
  },
  inputIcon: { marginRight: SPACING.sm },
  input: { flex: 1, color: COLORS.text, fontSize: FONTS.sizes.md },

  stepperRow:   { flexDirection: 'row', alignItems: 'center', gap: SPACING.xl },
  stepperBtn: {
    width: 44, height: 44, borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface, borderWidth: 1.5, borderColor: COLORS.border,
    alignItems: 'center', justifyContent: 'center',
  },
  stepperBtnDisabled: { opacity: 0.4 },
  stepperValue: { alignItems: 'center' },
  stepperNumber:{ color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  stepperUnit:  { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },

  includedSection: { paddingHorizontal: SPACING.lg, marginBottom: SPACING.lg },
  includedGrid:    { flexDirection: 'row', gap: SPACING.sm },
  includedItem: {
    flex: 1, backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    padding: SPACING.md, alignItems: 'center', gap: SPACING.sm,
    borderWidth: 1, borderColor: COLORS.border,
  },
  includedIcon: {
    width: 40, height: 40, borderRadius: RADIUS.md,
    backgroundColor: 'rgba(108,60,225,0.15)', alignItems: 'center', justifyContent: 'center',
  },
  includedLabel: {
    color: COLORS.textSecondary, fontSize: FONTS.sizes.xs,
    fontWeight: '600', textAlign: 'center',
  },

  footer: { padding: SPACING.lg, paddingBottom: SPACING.xxl, backgroundColor: COLORS.background },
  submittingContainer: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.md, gap: SPACING.md, borderWidth: 1, borderColor: 'rgba(108,60,225,0.3)',
  },
  submittingIcon: {
    width: 44, height: 44, borderRadius: RADIUS.full,
    backgroundColor: 'rgba(108,60,225,0.2)', alignItems: 'center', justifyContent: 'center',
  },
  submittingTitle:    { color: COLORS.text, fontWeight: '700', fontSize: FONTS.sizes.md },
  submittingSubtitle: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
});
