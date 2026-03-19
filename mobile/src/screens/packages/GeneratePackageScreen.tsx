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
  Modal,
  Platform,
} from 'react-native';
import DateTimePicker, { DateTimePickerEvent } from '@react-native-community/datetimepicker';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI } from '../../services/api';

// Tomorrow (minimum selectable date)
const tomorrow = (() => {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  d.setHours(0, 0, 0, 0);
  return d;
})();

const formatDisplay = (date: Date): string => {
  const dd   = String(date.getDate()).padStart(2, '0');
  const mm   = String(date.getMonth() + 1).padStart(2, '0');
  const yyyy = date.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
};

const toISO = (date: Date): string => date.toISOString().split('T')[0];

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

  const [destination, setDestination]             = useState('');
  const [departureLocation, setDepartureLocation] = useState('');
  const [selectedDate, setSelectedDate]           = useState<Date | null>(null);
  const [showPicker, setShowPicker]               = useState(false);
  // iOS: temp date while the picker is open (confirmed on "Done")
  const [tempDate, setTempDate]                   = useState<Date>(tomorrow);
  const [duration, setDuration]                   = useState(7);
  const [guests, setGuests]                       = useState(2);
  const [generating, setGenerating]               = useState(false);

  const pulseAnim = useRef(new Animated.Value(1)).current;

  const startPulse = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, { toValue: 1.05, duration: 600, useNativeDriver: true }),
        Animated.timing(pulseAnim, { toValue: 1, duration: 600, useNativeDriver: true }),
      ])
    ).start();
  };

  // Android: picker dismisses automatically on selection
  // iOS: picker stays open; confirmed via "Done" button
  const onDateChange = (event: DateTimePickerEvent, date?: Date) => {
    if (Platform.OS === 'android') {
      setShowPicker(false);
      if (event.type === 'set' && date) setSelectedDate(date);
    } else {
      if (date) setTempDate(date);
    }
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
    if (!selectedDate) {
      Alert.alert('Missing Date', 'Please select your departure date.');
      return;
    }
    if (duration < 3) {
      Alert.alert('Minimum Duration', 'Trip duration must be at least 3 days.');
      return;
    }

    setGenerating(true);
    startPulse();

    const isoStart  = toISO(selectedDate);
    const endDateObj = new Date(selectedDate);
    endDateObj.setDate(endDateObj.getDate() + duration);
    const endDate = toISO(endDateObj);

    try {
      await packagesAPI.generate({
        destination:       destination.trim(),
        startDate:         isoStart,
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

        {/* Departure Date — calendar picker */}
        <View style={styles.section}>
          <Text style={styles.label}>Departure Date *</Text>
          <TouchableOpacity
            style={styles.dateBtn}
            onPress={() => {
              setTempDate(selectedDate ?? tomorrow);
              setShowPicker(true);
            }}
            activeOpacity={0.8}
          >
            <Ionicons name="calendar-outline" size={20} color={COLORS.secondary} style={styles.inputIcon} />
            <Text style={[styles.dateBtnText, !selectedDate && styles.datePlaceholder]}>
              {selectedDate ? formatDisplay(selectedDate) : 'Select departure date'}
            </Text>
            <Ionicons name="chevron-down" size={16} color={COLORS.textMuted} />
          </TouchableOpacity>
        </View>

        {/* Android: native date dialog shown directly */}
        {Platform.OS === 'android' && showPicker && (
          <DateTimePicker
            value={tempDate}
            mode="date"
            display="default"
            minimumDate={tomorrow}
            onChange={onDateChange}
          />
        )}

        {/* iOS: date picker inside a modal with Done button */}
        {Platform.OS === 'ios' && (
          <Modal visible={showPicker} transparent animationType="slide">
            <View style={styles.modalOverlay}>
              <View style={styles.modalCard}>
                <View style={styles.modalHeader}>
                  <TouchableOpacity onPress={() => setShowPicker(false)}>
                    <Text style={styles.modalCancel}>Cancel</Text>
                  </TouchableOpacity>
                  <Text style={styles.modalTitle}>Departure Date</Text>
                  <TouchableOpacity onPress={() => { setSelectedDate(tempDate); setShowPicker(false); }}>
                    <Text style={styles.modalDone}>Done</Text>
                  </TouchableOpacity>
                </View>
                <DateTimePicker
                  value={tempDate}
                  mode="date"
                  display="inline"
                  minimumDate={tomorrow}
                  onChange={onDateChange}
                  themeVariant="dark"
                  accentColor={COLORS.secondary}
                  style={styles.iosPicker}
                />
              </View>
            </View>
          </Modal>
        )}

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

  // Date picker button
  dateBtn: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: COLORS.surface, borderRadius: RADIUS.md,
    borderWidth: 1, borderColor: COLORS.border,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm + 2,
  },
  dateBtnText:   { flex: 1, color: COLORS.text, fontSize: FONTS.sizes.md },
  datePlaceholder: { color: COLORS.textMuted },

  // iOS modal
  modalOverlay: {
    flex: 1, backgroundColor: 'rgba(0,0,0,0.6)',
    justifyContent: 'flex-end',
  },
  modalCard: {
    backgroundColor: COLORS.surface,
    borderTopLeftRadius: RADIUS.xl, borderTopRightRadius: RADIUS.xl,
    paddingBottom: SPACING.xxl,
  },
  modalHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingHorizontal: SPACING.lg, paddingVertical: SPACING.md,
    borderBottomWidth: 1, borderBottomColor: COLORS.border,
  },
  modalTitle:  { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700' },
  modalCancel: { color: COLORS.textMuted, fontSize: FONTS.sizes.md },
  modalDone:   { color: COLORS.secondary, fontSize: FONTS.sizes.md, fontWeight: '700' },
  iosPicker:   { alignSelf: 'center' },

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
