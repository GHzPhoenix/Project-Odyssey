import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

const Section = ({ title, children }: { title: string; children: string }) => (
  <View style={styles.section}>
    <Text style={styles.sectionTitle}>{title}</Text>
    <Text style={styles.body}>{children}</Text>
  </View>
);

export const PrivacyPolicyScreen: React.FC = () => {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Privacy Policy</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        {/* Meta */}
        <View style={styles.metaCard}>
          <Ionicons name="shield-checkmark-outline" size={20} color={COLORS.secondary} />
          <View style={{ flex: 1 }}>
            <Text style={styles.metaTitle}>Travel Odyssey — Privacy Policy</Text>
            <Text style={styles.metaDate}>Last updated: March 2026</Text>
          </View>
        </View>

        <Text style={styles.intro}>
          Your privacy matters to us. This Privacy Policy explains what personal data Travel Odyssey collects, how we use it, and your rights regarding that data. We are committed to handling your information responsibly and in compliance with applicable data protection laws, including the EU General Data Protection Regulation (GDPR).
        </Text>

        {/* Highlight card */}
        <View style={styles.highlightCard}>
          <Text style={styles.highlightTitle}>🔒 Our Privacy Commitment</Text>
          <Text style={styles.highlightBody}>
            We never sell your personal data to third parties. Your information is used only to provide and improve our travel concierge service.
          </Text>
        </View>

        <Section title="1. Data Controller">
          {`Travel Odyssey is the data controller responsible for your personal information.\n\nContact: support@travelodyssey.app\n\nFor any data protection enquiries, you may contact us directly at the above address.`}
        </Section>

        <Section title="2. What Data We Collect">
          {`We collect the following categories of personal data:\n\n Account Data\n• Full name\n• Email address\n• Encrypted password\n• Account creation date\n\n Travel Preferences\n• Travel style, budget, dietary restrictions\n• Activity preferences, cuisine preferences\n• Travel companion type, accommodation preference\n\n Trip Request Data\n• Destination and departure city\n• Travel dates and guest count\n• Special requirements or notes you provide\n\n Payment Data\n• Payment confirmation references (we do not store full card numbers — these are handled by Stripe and PayPal)\n• Transaction amounts and timestamps\n\n Technical Data\n• Device push notification token (for alerts)\n• App usage and feature interaction (aggregated, anonymous analytics)\n• IP address and general location (for security purposes)`}
        </Section>

        <Section title="3. How We Use Your Data">
          {`We use your personal data to:\n\n• Create and manage your account\n• Personalise your trip recommendations and curated packages\n• Process and manage your trip requests\n• Communicate with you about your requests and bookings\n• Process subscription and trip payments\n• Send you push notifications and emails you have opted into\n• Improve our service through aggregated usage analysis\n• Meet our legal and contractual obligations\n\nWe will only process your data where we have a lawful basis to do so — including your consent, the performance of a contract, or our legitimate interests.`}
        </Section>

        <Section title="4. How We Share Your Data">
          {`We do not sell your personal data. We may share your data with trusted third parties only where necessary:\n\n• Stripe and PayPal — to securely process payments\n• Expo (push notifications) — to deliver in-app alerts\n• Resend — to deliver transactional emails\n• Travel suppliers (airlines, hotels) — only the details necessary to confirm your booking (e.g. names and travel dates)\n• Cloud infrastructure providers — who process data on our behalf under strict data processing agreements\n\nAll third-party processors are required to handle your data in compliance with applicable data protection law.`}
        </Section>

        <Section title="5. Data Retention">
          {`We retain your personal data for as long as your account is active or as necessary to provide our services.\n\nSpecific retention periods:\n• Account data: retained while your account is active, then deleted within 90 days of account closure\n• Trip request data: retained for 3 years for business and legal record purposes\n• Payment records: retained for 7 years to comply with financial regulations\n• Anonymised analytics: retained indefinitely\n\nYou may request deletion of your account and personal data at any time (see Your Rights below).`}
        </Section>

        <Section title="6. Cookies and Tracking">
          {`The Travel Odyssey mobile app does not use cookies. We may use anonymised, aggregated analytics to understand how users interact with the app. This data cannot be used to identify you personally.`}
        </Section>

        <Section title="7. Push Notifications">
          {`We send push notifications to keep you informed about your trip requests, bookings, and account activity. You can manage push notification preferences at any time in your Profile settings.\n\nYou may disable notifications entirely through your device's system settings. This will not affect your ability to use the app, but you may miss important updates about your trips.`}
        </Section>

        <Section title="8. Data Security">
          {`We take appropriate technical and organisational measures to protect your data against unauthorised access, loss, or disclosure. These include:\n\n• Passwords are stored using industry-standard bcrypt hashing\n• All data is transmitted over encrypted HTTPS connections\n• Authentication uses time-limited JWT tokens\n• Payment data is handled exclusively by PCI-compliant payment processors\n• Access to personal data is restricted to authorised personnel only\n\nNo method of transmission over the internet is 100% secure. While we do everything we can to protect your data, we cannot guarantee absolute security.`}
        </Section>

        <Section title="9. Your Rights (GDPR)">
          {`If you are located in the European Economic Area, you have the following rights:\n\n• Right of access — request a copy of your personal data\n• Right to rectification — correct inaccurate or incomplete data\n• Right to erasure — request deletion of your personal data\n• Right to restrict processing — ask us to limit how we use your data\n• Right to data portability — receive your data in a structured, machine-readable format\n• Right to object — object to processing based on legitimate interests\n• Right to withdraw consent — where processing is based on consent, you may withdraw it at any time\n\nTo exercise any of these rights, please contact us at support@travelodyssey.app. We will respond within 30 days.`}
        </Section>

        <Section title="10. Children's Privacy">
          {`Travel Odyssey is not intended for use by children under the age of 16. We do not knowingly collect personal data from children. If you believe a child has provided us with their data, please contact us immediately and we will delete it.`}
        </Section>

        <Section title="11. International Transfers">
          {`Your data may be processed by our service providers in countries outside the European Economic Area. Where this occurs, we ensure appropriate safeguards are in place (such as Standard Contractual Clauses) to protect your data in accordance with GDPR requirements.`}
        </Section>

        <Section title="12. Changes to This Policy">
          {`We may update this Privacy Policy from time to time to reflect changes in our practices or applicable law. We will notify you of material changes via push notification or email. The date at the top of this page always reflects the most recent update.\n\nContinued use of the app after changes are posted constitutes your acceptance of the updated policy.`}
        </Section>

        <Section title="13. Contact & Complaints">
          {`For any privacy-related questions or concerns, please contact:\n\nsupport@travelodyssey.app\n\nIf you are not satisfied with our response, you have the right to lodge a complaint with your local data protection authority (e.g. the Data Protection Commission in Ireland, or the ICO in the UK).`}
        </Section>

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.xxl,
    paddingBottom: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  backBtn: {
    width: 38,
    height: 38,
    borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },

  scroll: { flex: 1 },
  content: { padding: SPACING.lg },

  metaCard: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.sm,
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    marginBottom: SPACING.lg,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  metaTitle: { color: COLORS.text, fontWeight: '700', fontSize: FONTS.sizes.sm },
  metaDate: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },

  intro: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
    lineHeight: 22,
    marginBottom: SPACING.lg,
  },

  highlightCard: {
    backgroundColor: 'rgba(108,60,225,0.12)',
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    marginBottom: SPACING.lg,
    borderWidth: 1,
    borderColor: 'rgba(108,60,225,0.25)',
  },
  highlightTitle: { color: COLORS.text, fontSize: FONTS.sizes.sm, fontWeight: '700', marginBottom: SPACING.xs },
  highlightBody: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 20 },

  section: { marginBottom: SPACING.lg },
  sectionTitle: {
    color: COLORS.text,
    fontSize: FONTS.sizes.md,
    fontWeight: '700',
    marginBottom: SPACING.sm,
  },
  body: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
    lineHeight: 22,
  },
});
