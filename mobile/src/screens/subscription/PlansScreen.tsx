import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';

const { width } = Dimensions.get('window');

const PLANS = [
  {
    id: 'explorer',
    name: 'Explorer',
    price: 29,
    yearlyPrice: 249,
    color: '#4A90D9',
    icon: 'compass',
    tagline: 'Perfect for occasional travelers',
    features: [
      '1 AI-generated package/month',
      'Access to curated deals',
      'Basic preference matching',
      'Email support',
      'Cancel anytime',
    ],
    notIncluded: ['Priority curation', 'Exclusive experiences', 'Concierge support'],
  },
  {
    id: 'voyager',
    name: 'Voyager',
    price: 59,
    yearlyPrice: 499,
    color: '#6C3CE1',
    icon: 'airplane',
    tagline: 'For the regular traveler',
    highlighted: true,
    features: [
      '3 AI-generated packages/month',
      'Full preference personalization',
      'Priority restaurant reservations',
      'Exclusive experiences access',
      'Chat support',
      'Cancel anytime',
    ],
    notIncluded: ['Unlimited packages', '24/7 concierge'],
  },
  {
    id: 'elite',
    name: 'Elite',
    price: 129,
    yearlyPrice: 999,
    color: '#F5A623',
    icon: 'diamond',
    tagline: 'The ultimate travel lifestyle',
    features: [
      'Unlimited AI packages',
      'Hyper-personalized curation',
      'Priority restaurant & hotel booking',
      'VIP experience access',
      '24/7 concierge support',
      'Family & group trip planning',
      'Cancel anytime',
    ],
    notIncluded: [],
  },
];

export const PlansScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const [billing, setBilling] = useState<'monthly' | 'yearly'>('monthly');
  const [selectedPlan, setSelectedPlan] = useState('voyager');

  const getPrice = (plan: typeof PLANS[0]) => {
    if (billing === 'yearly') {
      return Math.round(plan.yearlyPrice / 12);
    }
    return plan.price;
  };

  const getSaving = (plan: typeof PLANS[0]) => {
    const yearlySaving = plan.price * 12 - plan.yearlyPrice;
    return yearlySaving;
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Choose Your Plan</Text>
        <View style={{ width: 38 }} />
      </View>

      <ScrollView showsVerticalScrollIndicator={false}>
        <View style={styles.content}>
          {/* Headline */}
          <Text style={styles.title}>Travel More,{'\n'}Stress Less</Text>
          <Text style={styles.subtitle}>
            Subscribe to unlock AI-powered personalized travel experiences
          </Text>

          {/* Billing Toggle */}
          <View style={styles.billingToggle}>
            <TouchableOpacity
              style={[styles.billingOption, billing === 'monthly' && styles.billingOptionActive]}
              onPress={() => setBilling('monthly')}
            >
              <Text style={[styles.billingText, billing === 'monthly' && styles.billingTextActive]}>Monthly</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.billingOption, billing === 'yearly' && styles.billingOptionActive]}
              onPress={() => setBilling('yearly')}
            >
              <Text style={[styles.billingText, billing === 'yearly' && styles.billingTextActive]}>Annual</Text>
              <View style={styles.savingBadge}>
                <Text style={styles.savingBadgeText}>Save 30%</Text>
              </View>
            </TouchableOpacity>
          </View>

          {/* Plans */}
          {PLANS.map((plan) => {
            const isSelected = selectedPlan === plan.id;
            return (
              <TouchableOpacity
                key={plan.id}
                style={[
                  styles.planCard,
                  isSelected && { borderColor: plan.color, borderWidth: 2 },
                  plan.highlighted && styles.planHighlighted,
                ]}
                onPress={() => setSelectedPlan(plan.id)}
                activeOpacity={0.9}
              >
                {plan.highlighted && (
                  <View style={[styles.popularBadge, { backgroundColor: plan.color }]}>
                    <Text style={styles.popularText}>Most Popular</Text>
                  </View>
                )}

                <View style={styles.planTop}>
                  <View style={[styles.planIcon, { backgroundColor: plan.color + '25' }]}>
                    <Ionicons name={plan.icon as any} size={22} color={plan.color} />
                  </View>
                  <View style={styles.planTitleBlock}>
                    <Text style={styles.planName}>{plan.name}</Text>
                    <Text style={styles.planTagline}>{plan.tagline}</Text>
                  </View>
                  <View style={styles.planPriceBlock}>
                    <Text style={[styles.planPrice, { color: plan.color }]}>€{getPrice(plan)}</Text>
                    <Text style={styles.planPeriod}>/mo</Text>
                  </View>
                </View>

                {billing === 'yearly' && (
                  <View style={styles.yearlyNote}>
                    <Ionicons name="pricetag-outline" size={12} color={COLORS.success} />
                    <Text style={styles.yearlyNoteText}>Save €{getSaving(plan)} per year</Text>
                  </View>
                )}

                <View style={styles.planDivider} />

                {plan.features.map((feature, i) => (
                  <View key={i} style={styles.featureRow}>
                    <View style={[styles.featureCheck, { backgroundColor: plan.color + '20' }]}>
                      <Ionicons name="checkmark" size={12} color={plan.color} />
                    </View>
                    <Text style={styles.featureText}>{feature}</Text>
                  </View>
                ))}

                {plan.notIncluded.map((feature, i) => (
                  <View key={i} style={styles.featureRow}>
                    <View style={styles.featureCross}>
                      <Ionicons name="close" size={12} color={COLORS.textMuted} />
                    </View>
                    <Text style={styles.featureTextDisabled}>{feature}</Text>
                  </View>
                ))}

                {isSelected && (
                  <View style={[styles.selectedIndicator, { backgroundColor: plan.color }]}>
                    <Ionicons name="checkmark-circle" size={16} color={COLORS.white} />
                    <Text style={styles.selectedText}>Selected</Text>
                  </View>
                )}
              </TouchableOpacity>
            );
          })}

          {/* One-Time Option */}
          <View style={styles.oneTimeSection}>
            <View style={styles.dividerRow}>
              <View style={styles.dividerLine} />
              <Text style={styles.dividerLabel}>Don't travel regularly?</Text>
              <View style={styles.dividerLine} />
            </View>
            <TouchableOpacity
              style={styles.oneTimeCard}
              onPress={() => navigation.navigate('Payment', { planId: 'one-time', isOneTime: true })}
              activeOpacity={0.8}
            >
              <View style={styles.oneTimeLeft}>
                <View style={styles.oneTimeIcon}>
                  <Ionicons name="ticket-outline" size={20} color={COLORS.textSecondary} />
                </View>
                <View>
                  <Text style={styles.oneTimeTitle}>Pay Per Package</Text>
                  <Text style={styles.oneTimeSub}>No subscription needed. Buy individual packages.</Text>
                </View>
              </View>
              <Ionicons name="chevron-forward" size={18} color={COLORS.textMuted} />
            </TouchableOpacity>
          </View>
        </View>

        <View style={{ height: SPACING.xxxl + SPACING.xl }} />
      </ScrollView>

      {/* CTA Footer */}
      <View style={styles.footer}>
        <Button
          label={`Continue with ${PLANS.find(p => p.id === selectedPlan)?.name}`}
          onPress={() => navigation.navigate('Payment', { planId: selectedPlan })}
        />
        <Text style={styles.footerNote}>Cancel anytime · No hidden fees</Text>
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
  content: { paddingHorizontal: SPACING.lg, paddingTop: SPACING.md },
  title: { color: COLORS.text, fontSize: FONTS.sizes.xxxl, fontWeight: '800', marginBottom: SPACING.sm },
  subtitle: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, lineHeight: 24, marginBottom: SPACING.xl },
  billingToggle: {
    flexDirection: 'row',
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.full,
    padding: 3,
    marginBottom: SPACING.xl,
  },
  billingOption: {
    flex: 1, paddingVertical: SPACING.sm, borderRadius: RADIUS.full,
    alignItems: 'center', flexDirection: 'row', justifyContent: 'center', gap: SPACING.xs,
  },
  billingOptionActive: { backgroundColor: COLORS.secondary },
  billingText: { color: COLORS.textMuted, fontWeight: '600', fontSize: FONTS.sizes.sm },
  billingTextActive: { color: COLORS.white },
  savingBadge: {
    backgroundColor: COLORS.success, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.xs + 2, paddingVertical: 2,
  },
  savingBadgeText: { color: COLORS.white, fontSize: 9, fontWeight: '700' },
  planCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.lg, marginBottom: SPACING.md,
    borderWidth: 1.5, borderColor: COLORS.border,
    position: 'relative', overflow: 'hidden',
  },
  planHighlighted: {
    backgroundColor: 'rgba(108,60,225,0.08)',
  },
  popularBadge: {
    position: 'absolute', top: 0, right: SPACING.lg,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.xs,
    borderBottomLeftRadius: RADIUS.md, borderBottomRightRadius: RADIUS.md,
  },
  popularText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '700' },
  planTop: { flexDirection: 'row', alignItems: 'center', gap: SPACING.md, marginBottom: SPACING.md },
  planIcon: {
    width: 46, height: 46, borderRadius: RADIUS.md,
    alignItems: 'center', justifyContent: 'center',
  },
  planTitleBlock: { flex: 1 },
  planName: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '800' },
  planTagline: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },
  planPriceBlock: { flexDirection: 'row', alignItems: 'baseline' },
  planPrice: { fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  planPeriod: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm },
  yearlyNote: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.xs,
    backgroundColor: 'rgba(76,175,80,0.1)', borderRadius: RADIUS.md,
    padding: SPACING.xs, marginBottom: SPACING.md, alignSelf: 'flex-start',
  },
  yearlyNoteText: { color: COLORS.success, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  planDivider: { height: 1, backgroundColor: COLORS.border, marginBottom: SPACING.md },
  featureRow: { flexDirection: 'row', alignItems: 'center', gap: SPACING.sm, marginBottom: SPACING.sm },
  featureCheck: {
    width: 20, height: 20, borderRadius: RADIUS.full,
    alignItems: 'center', justifyContent: 'center',
  },
  featureCross: {
    width: 20, height: 20, borderRadius: RADIUS.full,
    alignItems: 'center', justifyContent: 'center',
    backgroundColor: COLORS.surfaceLight,
  },
  featureText: { color: COLORS.text, fontSize: FONTS.sizes.sm, flex: 1 },
  featureTextDisabled: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, flex: 1 },
  selectedIndicator: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.xs,
    borderRadius: RADIUS.full, paddingHorizontal: SPACING.md, paddingVertical: SPACING.xs,
    alignSelf: 'flex-start', marginTop: SPACING.md,
  },
  selectedText: { color: COLORS.white, fontSize: FONTS.sizes.sm, fontWeight: '700' },
  oneTimeSection: { marginTop: SPACING.md },
  dividerRow: { flexDirection: 'row', alignItems: 'center', gap: SPACING.sm, marginBottom: SPACING.md },
  dividerLine: { flex: 1, height: 1, backgroundColor: COLORS.border },
  dividerLabel: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
  oneTimeCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    padding: SPACING.md, flexDirection: 'row', alignItems: 'center',
    borderWidth: 1, borderColor: COLORS.border,
  },
  oneTimeLeft: { flexDirection: 'row', alignItems: 'center', gap: SPACING.md, flex: 1 },
  oneTimeIcon: {
    width: 44, height: 44, borderRadius: RADIUS.md,
    backgroundColor: COLORS.surfaceLight, alignItems: 'center', justifyContent: 'center',
  },
  oneTimeTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '600' },
  oneTimeSub: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2, maxWidth: 200 },
  footer: { padding: SPACING.lg, paddingBottom: SPACING.xxl, backgroundColor: COLORS.background },
  footerNote: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, textAlign: 'center', marginTop: SPACING.sm },
});
