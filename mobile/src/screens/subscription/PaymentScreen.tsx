import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation, useRoute, RouteProp } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useStripe } from '@stripe/stripe-react-native';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { stripeAPI, subscriptionAPI } from '../../services/api';
import { useStore } from '../../store/useStore';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

const PLAN_DETAILS: Record<string, { name: string; price: number; yearlyPrice: number; color: string }> = {
  explorer:  { name: 'Explorer',          price: 29,  yearlyPrice: 249,  color: '#4A90D9' },
  voyager:   { name: 'Voyager',           price: 59,  yearlyPrice: 499,  color: '#6C3CE1' },
  elite:     { name: 'Elite',             price: 129, yearlyPrice: 999,  color: '#F5A623' },
  'one-time':{ name: 'One-Time Package',  price: 0,   yearlyPrice: 0,    color: '#6C3CE1' }, // handled via Trips tab — not routed here
};

export const PaymentScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const route      = useRoute<RouteProp<RootStackParamList, 'Payment'>>();
  const { planId, isOneTime } = route.params;

  const [billing, setBilling]     = useState<'monthly' | 'yearly'>('monthly');
  const [processing, setProcessing] = useState(false);

  const plan  = PLAN_DETAILS[planId] || PLAN_DETAILS.voyager;
  const price = billing === 'yearly' ? Math.round(plan.yearlyPrice / 12) : plan.price;
  const total = billing === 'yearly' ? plan.yearlyPrice : plan.price;

  const { setMembership }               = useStore();
  const { initPaymentSheet, presentPaymentSheet } = useStripe();

  const handlePayment = async () => {
    // One-time purchases don't need payment processing in this flow
    if (isOneTime) {
      Alert.alert(
        '✦ Package Purchased',
        'Your package has been purchased! Check My Trips to view your booking.',
        [{ text: 'View Trips', onPress: () => navigation.navigate('Main') }]
      );
      return;
    }

    setProcessing(true);
    try {
      // 1. Create payment intent on the server
      const intentRes = await stripeAPI.createPaymentIntent(planId, billing);
      const { clientSecret } = intentRes.data;

      // 2. Initialise Stripe payment sheet
      const { error: initError } = await initPaymentSheet({
        paymentIntentClientSecret: clientSecret,
        merchantDisplayName: 'Travel Odyssey',
        style: 'alwaysDark',
      });

      if (initError) {
        Alert.alert('Payment Error', initError.message);
        return;
      }

      // 3. Present payment sheet to user
      const { error: presentError } = await presentPaymentSheet();
      if (presentError) {
        // User cancelled or card declined
        if (presentError.code !== 'Canceled') {
          Alert.alert('Payment Failed', presentError.message);
        }
        return;
      }

      // 4. Payment succeeded — record subscription (webhook also handles this as backup)
      const subRes = await subscriptionAPI.subscribe(planId, billing);
      const sub    = subRes.data?.subscription;
      if (sub) {
        setMembership({
          id:        Date.now(),
          type:      planId as any,
          expiresAt: sub.expiresAt,
          status:    'active',
        });
      }

      Alert.alert(
        '✦ Subscription Active!',
        `Welcome to ${plan.name}! Your subscription is now active.`,
        [{ text: 'Get Started', onPress: () => navigation.navigate('Main') }]
      );
    } catch (err: any) {
      const msg = err?.response?.data?.error || 'Payment failed. Please try again.';
      Alert.alert('Payment Failed', msg);
    } finally {
      setProcessing(false);
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>{isOneTime ? 'Purchase Package' : 'Subscribe'}</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView style={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Plan Summary */}
        <View style={[styles.planSummary, { borderColor: plan.color + '50' }]}>
          <View style={[styles.planIcon, { backgroundColor: plan.color + '20' }]}>
            <Ionicons name="diamond-outline" size={22} color={plan.color} />
          </View>
          <View style={styles.planInfo}>
            <Text style={styles.planName}>{plan.name}</Text>
            {!isOneTime && (
              <Text style={styles.planBilling}>
                {billing === 'yearly' ? `€${plan.yearlyPrice}/year` : `€${plan.price}/month`}
              </Text>
            )}
          </View>
          {!isOneTime && (
            <View>
              <Text style={[styles.planPrice, { color: plan.color }]}>€{price}</Text>
              <Text style={styles.planPeriod}>/month</Text>
            </View>
          )}
        </View>

        {/* Billing Toggle (not for one-time) */}
        {!isOneTime && (
          <View style={styles.section}>
            <Text style={styles.label}>Billing Period</Text>
            <View style={styles.billingToggle}>
              <TouchableOpacity
                style={[styles.billingOption, billing === 'monthly' && styles.billingActive]}
                onPress={() => setBilling('monthly')}
              >
                <Text style={[styles.billingText, billing === 'monthly' && styles.billingTextActive]}>
                  Monthly
                </Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.billingOption, billing === 'yearly' && styles.billingActive]}
                onPress={() => setBilling('yearly')}
              >
                <Text style={[styles.billingText, billing === 'yearly' && styles.billingTextActive]}>
                  Annual
                </Text>
                <View style={styles.saveBadge}>
                  <Text style={styles.saveBadgeText}>Save 30%</Text>
                </View>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {/* Payment Method */}
        <View style={styles.section}>
          <Text style={styles.label}>Payment Method</Text>
          <View style={styles.paymentMethod}>
            <Ionicons name="card-outline" size={20} color={COLORS.secondary} />
            <Text style={styles.paymentText}>Credit / Debit Card via Stripe</Text>
            <View style={styles.paymentBadge}>
              <Text style={styles.paymentBadgeText}>Secure</Text>
            </View>
          </View>
          <View style={styles.paymentNote}>
            <Ionicons name="lock-closed-outline" size={12} color={COLORS.textMuted} />
            <Text style={styles.paymentNoteText}>
              Payments processed securely by Stripe. Card details are never stored on our servers.
            </Text>
          </View>
        </View>

        {/* Order Summary */}
        <View style={styles.section}>
          <Text style={styles.label}>Order Summary</Text>
          <View style={styles.orderCard}>
            <View style={styles.orderRow}>
              <Text style={styles.orderLabel}>{plan.name} Plan</Text>
              <Text style={styles.orderValue}>€{price}/mo</Text>
            </View>
            {billing === 'yearly' && !isOneTime && (
              <View style={styles.orderRow}>
                <Text style={styles.orderLabel}>Annual discount</Text>
                <Text style={[styles.orderValue, { color: COLORS.success }]}>
                  -€{plan.price * 12 - plan.yearlyPrice}
                </Text>
              </View>
            )}
            <View style={styles.orderDivider} />
            <View style={styles.orderRow}>
              <Text style={styles.orderTotalLabel}>Total {billing === 'yearly' ? 'today' : 'per month'}</Text>
              <Text style={styles.orderTotal}>€{total}</Text>
            </View>
          </View>
        </View>

        {/* Trust Badges */}
        <View style={styles.trustRow}>
          {[
            { icon: 'shield-checkmark-outline', text: 'Stripe Secured' },
            { icon: 'refresh-outline',          text: 'Cancel Anytime' },
            { icon: 'star-outline',             text: '4.9 Rating' },
          ].map((t, i) => (
            <View key={i} style={styles.trustItem}>
              <Ionicons name={t.icon as any} size={18} color={COLORS.textSecondary} />
              <Text style={styles.trustText}>{t.text}</Text>
            </View>
          ))}
        </View>

        <View style={{ height: SPACING.xxxl + SPACING.xl }} />
      </ScrollView>

      <View style={styles.footer}>
        <Button
          label={processing ? 'Processing...' : `Pay €${total}`}
          onPress={handlePayment}
          loading={processing}
        />
        <Text style={styles.footerNote}>
          {isOneTime
            ? 'One-time payment. No recurring charges.'
            : `You'll be charged €${total} ${billing === 'yearly' ? 'today, then annually' : 'monthly'}. Cancel anytime.`}
        </Text>
      </View>
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
  scroll: { flex: 1 },
  planSummary: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.md,
    marginHorizontal: SPACING.lg, marginBottom: SPACING.lg,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md,
    borderWidth: 1.5,
  },
  planIcon: {
    width: 48, height: 48, borderRadius: RADIUS.md,
    alignItems: 'center', justifyContent: 'center',
  },
  planInfo: { flex: 1 },
  planName: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  planBilling: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, marginTop: 2 },
  planPrice: { fontSize: FONTS.sizes.xl, fontWeight: '800', textAlign: 'right' },
  planPeriod: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, textAlign: 'right' },
  section: { paddingHorizontal: SPACING.lg, marginBottom: SPACING.lg },
  label: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight: '600', letterSpacing: 0.5, marginBottom: SPACING.sm },
  billingToggle: {
    flexDirection: 'row', backgroundColor: COLORS.surface,
    borderRadius: RADIUS.full, padding: 3,
  },
  billingOption: {
    flex: 1, paddingVertical: SPACING.sm, borderRadius: RADIUS.full,
    alignItems: 'center', flexDirection: 'row', justifyContent: 'center', gap: SPACING.xs,
  },
  billingActive: { backgroundColor: COLORS.secondary },
  billingText: { color: COLORS.textMuted, fontWeight: '600', fontSize: FONTS.sizes.sm },
  billingTextActive: { color: COLORS.white },
  saveBadge: {
    backgroundColor: COLORS.success, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.xs + 2, paddingVertical: 2,
  },
  saveBadgeText: { color: COLORS.white, fontSize: 9, fontWeight: '700' },
  paymentMethod: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.md,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  paymentText: { color: COLORS.text, fontSize: FONTS.sizes.md, flex: 1 },
  paymentBadge: {
    backgroundColor: 'rgba(76,175,80,0.15)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  paymentBadgeText: { color: COLORS.success, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  paymentNote: { flexDirection: 'row', alignItems: 'flex-start', gap: 6, marginTop: SPACING.sm },
  paymentNoteText: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, flex: 1, lineHeight: 18 },
  orderCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  orderRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: SPACING.sm },
  orderLabel: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md },
  orderValue: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '600' },
  orderDivider: { height: 1, backgroundColor: COLORS.border, marginBottom: SPACING.sm },
  orderTotalLabel: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700' },
  orderTotal: { color: COLORS.accent, fontSize: FONTS.sizes.xl, fontWeight: '800' },
  trustRow: {
    flexDirection: 'row', justifyContent: 'space-around',
    marginHorizontal: SPACING.lg, marginBottom: SPACING.lg,
  },
  trustItem: { alignItems: 'center', gap: SPACING.xs },
  trustText: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, textAlign: 'center' },
  footer: { padding: SPACING.lg, paddingBottom: SPACING.xxl },
  footerNote: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, textAlign: 'center', marginTop: SPACING.sm, lineHeight: 18 },
});
