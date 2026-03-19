import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Linking,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

interface Section {
  title: string;
  icon: keyof typeof Ionicons.glyphMap;
  body: string;
}

const SECTIONS: Section[] = [
  {
    title: 'Data We Collect',
    icon:  'document-text-outline',
    body:  'We collect the information you provide when creating an account (name, email, password), your travel preferences, trip requests, and booking history. We also collect your device push notification token when you grant permission, solely to send you trip-related notifications.',
  },
  {
    title: 'How We Use Your Data',
    icon:  'analytics-outline',
    body:  'Your data is used exclusively to deliver the Travel Odyssey service: processing your trip requests, sending you notifications when your trip is ready, and personalising your experience. We never sell your data to third parties.',
  },
  {
    title: 'Payment Security',
    icon:  'card-outline',
    body:  'All payments are processed securely by Stripe, a PCI-DSS Level 1 certified provider. We never store your card details on our servers. Your payment information is transmitted directly to Stripe using industry-standard TLS encryption.',
  },
  {
    title: 'Data Retention',
    icon:  'time-outline',
    body:  'We retain your account data for as long as your account is active. Trip requests and bookings are kept for accounting and legal compliance purposes. You may request deletion of your account and associated data at any time by contacting us.',
  },
  {
    title: 'Your Rights',
    icon:  'shield-checkmark-outline',
    body:  'You have the right to access, correct, or delete your personal data. You can update your preferences and profile information at any time in the app. To request a full data export or account deletion, contact us at privacy@travelodyssey.com.',
  },
  {
    title: 'Cookies & Analytics',
    icon:  'pie-chart-outline',
    body:  'The mobile app does not use browser cookies. We may collect anonymous crash reports and usage analytics to improve app stability. This data is anonymised and cannot be used to identify you.',
  },
  {
    title: 'Third-Party Services',
    icon:  'link-outline',
    body:  'We use the following third-party services to operate Travel Odyssey: Stripe (payments), Resend (email notifications), Expo (push notifications), and Railway (server hosting). Each service processes only the minimum data required for their function and operates under their own privacy policies.',
  },
  {
    title: 'Contact Us',
    icon:  'mail-outline',
    body:  'For any privacy concerns, data requests, or questions about this policy, please contact us at privacy@travelodyssey.com. We aim to respond within 5 business days.',
  },
];

export const PrivacySecurityScreen: React.FC = () => {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Privacy & Security</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.scroll}>
        {/* Intro */}
        <View style={styles.introBanner}>
          <Ionicons name="shield-checkmark" size={32} color={COLORS.secondary} />
          <View style={{ flex: 1 }}>
            <Text style={styles.introTitle}>Your privacy matters</Text>
            <Text style={styles.introSub}>Last updated: March 2026</Text>
          </View>
        </View>

        <Text style={styles.introBody}>
          Travel Odyssey is committed to protecting your personal information. This page explains what data we collect, why we collect it, and how we keep it safe.
        </Text>

        {SECTIONS.map((s, i) => (
          <View key={i} style={styles.sectionCard}>
            <View style={styles.sectionHeader}>
              <View style={styles.sectionIcon}>
                <Ionicons name={s.icon} size={18} color={COLORS.secondary} />
              </View>
              <Text style={styles.sectionTitle}>{s.title}</Text>
            </View>
            <Text style={styles.sectionBody}>{s.body}</Text>
          </View>
        ))}

        {/* Contact button */}
        <TouchableOpacity
          style={styles.contactBtn}
          onPress={() => Linking.openURL('mailto:privacy@travelodyssey.com')}
          activeOpacity={0.8}
        >
          <Ionicons name="mail-outline" size={18} color={COLORS.white} />
          <Text style={styles.contactBtnText}>Contact Privacy Team</Text>
        </TouchableOpacity>

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

  introBanner: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.md,
    backgroundColor: 'rgba(108,60,225,0.12)', borderRadius: RADIUS.xl,
    padding: SPACING.md, marginBottom: SPACING.md,
    borderWidth: 1, borderColor: 'rgba(108,60,225,0.25)',
  },
  introTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  introSub:   { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },
  introBody:  { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 22, marginBottom: SPACING.lg },

  sectionCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.md, marginBottom: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  sectionHeader: { flexDirection: 'row', alignItems: 'center', gap: SPACING.sm, marginBottom: SPACING.sm },
  sectionIcon: {
    width: 36, height: 36, borderRadius: RADIUS.md,
    backgroundColor: 'rgba(108,60,225,0.12)', alignItems: 'center', justifyContent: 'center',
  },
  sectionTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700', flex: 1 },
  sectionBody:  { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 22 },

  contactBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: SPACING.sm,
    backgroundColor: COLORS.secondary, borderRadius: RADIUS.xl,
    paddingVertical: SPACING.md, marginTop: SPACING.md,
  },
  contactBtnText: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight: '700' },
});
