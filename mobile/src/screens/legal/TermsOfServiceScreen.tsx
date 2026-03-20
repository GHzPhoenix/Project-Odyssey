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

export const TermsOfServiceScreen: React.FC = () => {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Terms of Service</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        {/* Meta */}
        <View style={styles.metaCard}>
          <Ionicons name="document-text-outline" size={20} color={COLORS.secondary} />
          <View style={{ flex: 1 }}>
            <Text style={styles.metaTitle}>Travel Odyssey — Terms of Service</Text>
            <Text style={styles.metaDate}>Last updated: March 2026</Text>
          </View>
        </View>

        <Text style={styles.intro}>
          Please read these Terms of Service carefully before using the Travel Odyssey app. By creating an account or using our services, you agree to be bound by these terms.
        </Text>

        <Section title="1. About Our Service">
          {`Travel Odyssey is a personal travel concierge service. We manually research, build, and present custom trip packages based on your preferences and requests. We do not operate as an automated booking platform or a licensed travel agent in all jurisdictions.\n\nAll packages presented through our platform are curated proposals prepared by the Travel Odyssey team. We do not hold inventory, and trip availability is subject to confirmation with third-party providers.`}
        </Section>

        <Section title="2. User Accounts">
          {`To use Travel Odyssey, you must create an account. You are responsible for:\n\n• Providing accurate and up-to-date information\n• Keeping your password confidential\n• All activity that occurs under your account\n\nWe reserve the right to suspend or terminate accounts that violate these terms or engage in fraudulent activity.`}
        </Section>

        <Section title="3. Trip Requests">
          {`When you submit a trip request, you are initiating a consultation with our team. Submitting a request does not constitute a confirmed booking.\n\nOur team will review your request, research available options, and present you with a curated package and price. You are under no obligation to accept any package presented.\n\nWe reserve the right to decline requests that are outside our operational scope.`}
        </Section>

        <Section title="4. Pricing and Quotes">
          {`All prices are displayed in Euros (€) unless otherwise stated and include VAT where applicable.\n\nQuotes presented by our team are valid for the period specified on the quote (typically 48–72 hours). After expiry, prices may change due to fluctuations in flight, hotel, and service costs.\n\nTravel Odyssey is not responsible for price changes that occur after a quote has expired.`}
        </Section>

        <Section title="5. Payments">
          {`Payments are processed securely via Stripe or PayPal. By making a payment, you confirm that you are authorised to use the payment method provided.\n\nSubscription fees are billed monthly or annually as selected. Subscriptions renew automatically unless cancelled before the renewal date.\n\nAll payment transactions are subject to the payment provider's own terms and conditions.`}
        </Section>

        <Section title="6. Cancellations and Refunds">
          {`Our cancellation and refund policy depends on the status of your booking:\n\n• Before payment: You may cancel at any time at no charge.\n• After payment, before booking begins: A full refund may be available subject to review.\n• After booking has commenced: Cancellation may be subject to penalties imposed by airlines, hotels, or other service providers. Non-refundable costs will be deducted from any refund.\n• After documents are issued: Refunds are subject strictly to the policies of third-party providers.\n\nRefund requests must be submitted through the app. We aim to process all refunds within 5–10 business days.`}
        </Section>

        <Section title="7. Memberships">
          {`Membership plans (Explorer, Voyager, Elite) grant access to a set number of custom trip requests per calendar month. Unused requests do not roll over to the following month.\n\nMemberships may be upgraded, downgraded, or cancelled at any time. Changes take effect at the start of the next billing period.\n\nTravel Odyssey reserves the right to modify membership pricing or features with 30 days' notice.`}
        </Section>

        <Section title="8. Limitation of Liability">
          {`Travel Odyssey acts as an intermediary between users and third-party travel providers (airlines, hotels, tour operators). We are not responsible for:\n\n• Service failures, cancellations, or changes by third-party providers\n• Events outside our reasonable control (force majeure, natural disasters, strikes)\n• Travel delays or missed connections\n• Loss or damage to personal belongings during travel\n\nWe strongly recommend that all users obtain comprehensive travel insurance prior to travel.`}
        </Section>

        <Section title="9. Travel Documents">
          {`Users are solely responsible for ensuring they hold valid passports, visas, and any other documentation required for their trip. Travel Odyssey does not provide immigration or visa advice.\n\nEntry requirements vary by destination and nationality. Please verify all requirements with the relevant embassy or consulate before travel.`}
        </Section>

        <Section title="10. Intellectual Property">
          {`All content within the Travel Odyssey app — including text, images, itineraries, and branding — is the property of Travel Odyssey and may not be reproduced, distributed, or used without prior written consent.`}
        </Section>

        <Section title="11. Changes to These Terms">
          {`We may update these Terms of Service from time to time. Significant changes will be communicated via push notification or email. Continued use of the app after changes are posted constitutes your acceptance of the updated terms.`}
        </Section>

        <Section title="12. Governing Law">
          {`These terms are governed by the laws of the European Union and the jurisdiction in which Travel Odyssey operates. Any disputes shall be resolved through the courts of that jurisdiction.`}
        </Section>

        <Section title="13. Contact Us">
          {`If you have any questions about these Terms of Service, please contact us at:\n\nsupport@travelodyssey.app\n\nWe aim to respond to all enquiries within 2 business days.`}
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
    paddingBottom: SPACING.lg,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },

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
