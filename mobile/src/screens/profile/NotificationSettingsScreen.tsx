import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Platform,
  Linking,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

interface NotifItem {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  description: string;
  color?: string;
}

const NOTIFICATION_TYPES: NotifItem[] = [
  {
    icon:  'checkmark-circle',
    title: 'Trip Ready',
    description: 'Receive a push notification and email the moment your custom trip is crafted and ready for payment.',
    color: '#C9A84C',
  },
  {
    icon:  'receipt-outline',
    title: 'Payment Confirmed',
    description: 'A confirmation notification when your trip payment has been processed successfully.',
    color: '#4CAF50',
  },
  {
    icon:  'information-circle-outline',
    title: 'Trip Updates',
    description: 'Any important updates or changes to your upcoming trips or bookings.',
    color: COLORS.secondary,
  },
  {
    icon:  'sparkles-outline',
    title: 'New Deals',
    description: 'Occasional notifications about exclusive deals and special offers tailored to your preferences.',
    color: COLORS.accent,
  },
];

export const NotificationSettingsScreen: React.FC = () => {
  const navigation = useNavigation();

  const openSystemSettings = () => {
    if (Platform.OS === 'ios') {
      Linking.openURL('app-settings:');
    } else {
      Linking.openSettings();
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
        <Text style={styles.headerTitle}>Notifications</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.scroll}>
        {/* Info banner */}
        <View style={styles.infoBanner}>
          <Ionicons name="notifications" size={28} color={COLORS.secondary} />
          <View style={{ flex: 1 }}>
            <Text style={styles.infoTitle}>Stay in the loop</Text>
            <Text style={styles.infoSub}>We'll notify you when your trip is ready</Text>
          </View>
        </View>

        <Text style={styles.intro}>
          Travel Odyssey sends notifications to keep you updated on your trip requests. Enable notifications in your device settings to make sure you never miss a moment.
        </Text>

        {/* Enable button */}
        <TouchableOpacity style={styles.enableBtn} onPress={openSystemSettings} activeOpacity={0.85}>
          <Ionicons name="settings-outline" size={18} color={COLORS.white} />
          <Text style={styles.enableBtnText}>Open Notification Settings</Text>
        </TouchableOpacity>

        {/* Notification types */}
        <Text style={styles.sectionTitle}>What we'll notify you about</Text>
        {NOTIFICATION_TYPES.map((n, i) => (
          <View key={i} style={styles.notifCard}>
            <View style={[styles.notifIcon, { backgroundColor: (n.color || COLORS.secondary) + '20' }]}>
              <Ionicons name={n.icon} size={20} color={n.color || COLORS.secondary} />
            </View>
            <View style={styles.notifText}>
              <Text style={styles.notifTitle}>{n.title}</Text>
              <Text style={styles.notifDesc}>{n.description}</Text>
            </View>
          </View>
        ))}

        {/* Note */}
        <View style={styles.noteCard}>
          <Ionicons name="lock-closed-outline" size={16} color={COLORS.textMuted} />
          <Text style={styles.noteText}>
            We respect your privacy. Notifications are sent only for events directly related to your account and trips. You can disable all notifications at any time through your device settings.
          </Text>
        </View>

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md,
  },
  backBtn: {
    width: 38, height: 38, borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface, alignItems: 'center', justifyContent: 'center',
  },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },

  scroll: { paddingHorizontal: SPACING.lg, paddingBottom: SPACING.lg },

  infoBanner: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.md,
    backgroundColor: 'rgba(108,60,225,0.12)', borderRadius: RADIUS.xl,
    padding: SPACING.md, marginBottom: SPACING.md,
    borderWidth: 1, borderColor: 'rgba(108,60,225,0.25)',
  },
  infoTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  infoSub:   { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },

  intro: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 22, marginBottom: SPACING.lg },

  enableBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: SPACING.sm,
    backgroundColor: COLORS.secondary, borderRadius: RADIUS.xl,
    paddingVertical: SPACING.md, marginBottom: SPACING.xl,
  },
  enableBtnText: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight: '700' },

  sectionTitle: {
    color: COLORS.textSecondary, fontSize: FONTS.sizes.sm,
    fontWeight: '600', letterSpacing: 0.5, marginBottom: SPACING.md,
  },
  notifCard: {
    flexDirection: 'row', alignItems: 'flex-start', gap: SPACING.md,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.md, marginBottom: SPACING.sm,
    borderWidth: 1, borderColor: COLORS.border,
  },
  notifIcon: {
    width: 42, height: 42, borderRadius: RADIUS.md,
    alignItems: 'center', justifyContent: 'center', flexShrink: 0,
  },
  notifText: { flex: 1 },
  notifTitle:{ color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700', marginBottom: 3 },
  notifDesc: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 20 },

  noteCard: {
    flexDirection: 'row', alignItems: 'flex-start', gap: SPACING.sm,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.md, marginTop: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  noteText: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, lineHeight: 20, flex: 1 },
});
