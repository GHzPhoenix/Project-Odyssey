import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Image,
  Dimensions,
  StatusBar,
  RefreshControl,
  ActivityIndicator,
  Animated,
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { PackageCard } from '../../components/PackageCard';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI, subscriptionAPI } from '../../services/api';

const { width, height } = Dimensions.get('window');

const FEATURED_DESTINATIONS = [
  {
    name: 'Santorini',
    country: 'Greece',
    emoji: '🇬🇷',
    tag: 'Most Popular',
    img: 'https://images.unsplash.com/photo-1570077188670-e3a8d69ac5ff?w=600',
  },
  {
    name: 'Tokyo',
    country: 'Japan',
    emoji: '🇯🇵',
    tag: 'Trending',
    img: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=600',
  },
  {
    name: 'Bali',
    country: 'Indonesia',
    emoji: '🇮🇩',
    tag: 'Bestseller',
    img: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=600',
  },
  {
    name: 'Maldives',
    country: 'Maldives',
    emoji: '🇲🇻',
    tag: 'Luxury',
    img: 'https://images.unsplash.com/photo-1506953823976-52e1fdc0149a?w=600',
  },
  {
    name: 'Dubai',
    country: 'UAE',
    emoji: '🇦🇪',
    tag: 'Iconic',
    img: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=600',
  },
  {
    name: 'Paris',
    country: 'France',
    emoji: '🇫🇷',
    tag: 'Romance',
    img: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=600',
  },
  {
    name: 'Amalfi',
    country: 'Italy',
    emoji: '🇮🇹',
    tag: 'Hidden Gem',
    img: 'https://images.unsplash.com/photo-1533587851505-d119e13fa0d7?w=600',
  },
  {
    name: 'Kyoto',
    country: 'Japan',
    emoji: '🇯🇵',
    tag: 'Culture',
    img: 'https://images.unsplash.com/photo-1528360983277-13d401cdc186?w=600',
  },
];

const HOW_IT_WORKS = [
  {
    step: '01',
    icon: 'chatbubble-ellipses-outline' as const,
    title: 'Tell Us Your Dream',
    desc: 'Share your destination, dates & style',
  },
  {
    step: '02',
    icon: 'construct-outline' as const,
    title: 'We Craft Your Trip',
    desc: 'Our expert builds a personalised package',
  },
  {
    step: '03',
    icon: 'airplane-outline' as const,
    title: 'You Just Travel',
    desc: 'Everything is handled — just pack & go',
  },
];

const DEST_IMAGES: Record<string, string> = {
  London: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=800',
  Tokyo: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=800',
  Paris: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=800',
  Dubai: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=800',
  Bali: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=800',
  Rome: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=800',
  Santorini: 'https://images.unsplash.com/photo-1570077188670-e3a8d69ac5ff?w=800',
  Barcelona: 'https://images.unsplash.com/photo-1558642452-9d2a7deb7f62?w=800',
  Maldives: 'https://images.unsplash.com/photo-1506953823976-52e1fdc0149a?w=800',
  Amalfi: 'https://images.unsplash.com/photo-1533587851505-d119e13fa0d7?w=800',
  Kyoto: 'https://images.unsplash.com/photo-1528360983277-13d401cdc186?w=800',
};

const safeParseJSON = (raw: any, fallback: any) => {
  if (!raw || raw === 'null') return fallback;
  if (typeof raw !== 'string') return raw;
  try { return JSON.parse(raw); } catch { return fallback; }
};

const dealToPackage = (deal: any) => {
  const loc = deal.location || deal.title || '';
  const duration =
    deal.duration ||
    (deal.start_date && deal.end_date
      ? Math.max(1, Math.ceil((new Date(deal.end_date).getTime() - new Date(deal.start_date).getTime()) / 86400000))
      : 7);
  const included = safeParseJSON(deal.included_json, null);
  const highlights = safeParseJSON(deal.highlights_json, []);
  return {
    id: String(deal.id),
    destination: loc,
    country: deal.country || loc,
    startDate: deal.start_date || '',
    endDate: deal.end_date || '',
    duration,
    coverImage:
      deal.image_url || DEST_IMAGES[loc] || 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=800',
    price: deal.price,
    rating: deal.rating || 4.5,
    reviewCount: deal.review_count || Math.floor(Math.random() * 300 + 50),
    badge: deal.badge || undefined,
    isAIGenerated: false,
    summary: deal.summary || deal.description || '',
    itinerary: safeParseJSON(deal.itinerary_json, []),
    included: included || (deal.activities ? deal.activities.split(',').map((a: string) => a.trim()) : []),
    highlights,
    flight: safeParseJSON(deal.flight_json, null),
    hotel: safeParseJSON(deal.hotel_json, null),
  };
};

export const HomeScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { user, setMembership } = useStore();
  const [refreshing, setRefreshing] = useState(false);
  const [packages, setPackages] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Fade-in animation on mount
  const fadeAnim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    Animated.timing(fadeAnim, { toValue: 1, duration: 600, useNativeDriver: true }).start();
  }, []);

  const loadData = useCallback(async () => {
    try {
      const [dealsRes, membershipRes] = await Promise.allSettled([
        packagesAPI.getFeatured(),
        subscriptionAPI.getMembership(),
      ]);
      if (dealsRes.status === 'fulfilled') {
        const deals = dealsRes.value.data;
        setPackages((Array.isArray(deals) ? deals : []).map(dealToPackage));
      }
      if (membershipRes.status === 'fulfilled' && membershipRes.value.data?.membership_type) {
        const m = membershipRes.value.data;
        setMembership({
          id: m.id,
          type: m.membership_type,
          expiresAt: m.membership_expires,
          status: new Date(m.membership_expires) > new Date() ? 'active' : 'expired',
        });
      }
    } catch {}
    setLoading(false);
  }, [setMembership]);

  useEffect(() => { loadData(); }, [loadData]);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const greeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good morning';
    if (hour < 18) return 'Good afternoon';
    return 'Good evening';
  };

  const firstName = user?.name?.split(' ')[0] || 'Explorer';

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <Animated.View style={{ flex: 1, opacity: fadeAnim }}>
        <ScrollView
          showsVerticalScrollIndicator={false}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={COLORS.secondary} />
          }
        >
          {/* ─── HERO ─────────────────────────────────────────── */}
          <View style={styles.heroContainer}>
            <Image
              source={{ uri: 'https://images.unsplash.com/photo-1476514525535-07fb3b4ae5f1?w=900' }}
              style={styles.heroBg}
              resizeMode="cover"
            />
            {/* Dark gradient overlay */}
            <LinearGradient
              colors={['rgba(13,10,30,0.25)', 'rgba(13,10,30,0.75)', 'rgba(13,10,30,1)']}
              style={StyleSheet.absoluteFillObject}
            />

            {/* Header inside hero */}
            <View style={styles.heroHeader}>
              <View>
                <Text style={styles.greeting}>{greeting()},</Text>
                <Text style={styles.userName}>{firstName} ✦</Text>
              </View>
              <TouchableOpacity
                style={styles.notifBtn}
                onPress={() => (navigation as any).navigate('NotificationSettings')}
              >
                <Ionicons name="notifications-outline" size={20} color={COLORS.white} />
                <View style={styles.notifDot} />
              </TouchableOpacity>
            </View>

            {/* Hero text */}
            <View style={styles.heroBody}>
              <View style={styles.heroBadge}>
                <Ionicons name="sparkles" size={12} color={COLORS.accent} />
                <Text style={styles.heroBadgeText}>Personal Travel Concierge</Text>
              </View>
              <Text style={styles.heroTitle}>Where will you{'\n'}explore next?</Text>
              <Text style={styles.heroSubtitle}>
                Tell us your dream destination — we craft every detail for you.
              </Text>

              {/* CTA Row */}
              <View style={styles.heroCTARow}>
                <TouchableOpacity
                  style={styles.heroPrimaryBtn}
                  onPress={() => navigation.navigate('GeneratePackage')}
                  activeOpacity={0.85}
                >
                  <Ionicons name="paper-plane-outline" size={16} color={COLORS.primary} />
                  <Text style={styles.heroPrimaryBtnText}>Request a Trip</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={styles.heroSecondaryBtn}
                  onPress={() => (navigation as any).navigate('AIChat')}
                  activeOpacity={0.85}
                >
                  <Ionicons name="chatbubble-ellipses-outline" size={16} color={COLORS.white} />
                  <Text style={styles.heroSecondaryBtnText}>Ask Odyssey</Text>
                </TouchableOpacity>
              </View>
            </View>

            {/* Stats bar */}
            <View style={styles.statsBar}>
              {[
                { value: '200+', label: 'Trips Crafted' },
                { value: '40+', label: 'Destinations' },
                { value: '4.9★', label: 'Avg Rating' },
              ].map((stat, i) => (
                <React.Fragment key={stat.label}>
                  {i > 0 && <View style={styles.statsDivider} />}
                  <View style={styles.statItem}>
                    <Text style={styles.statValue}>{stat.value}</Text>
                    <Text style={styles.statLabel}>{stat.label}</Text>
                  </View>
                </React.Fragment>
              ))}
            </View>
          </View>

          {/* ─── TOP DESTINATIONS ─────────────────────────────── */}
          <View style={styles.section}>
            <View style={styles.sectionHeader}>
              <Text style={styles.sectionTitle}>Top Destinations</Text>
              <Text style={styles.sectionHint}>Tap to plan your trip</Text>
            </View>
            <ScrollView
              horizontal
              showsHorizontalScrollIndicator={false}
              contentContainerStyle={styles.destRow}
              decelerationRate="fast"
              snapToInterval={152}
              snapToAlignment="start"
            >
              {FEATURED_DESTINATIONS.map((dest) => (
                <TouchableOpacity
                  key={dest.name}
                  style={styles.destCard}
                  onPress={() =>
                    navigation.navigate('GeneratePackage', {
                      destination: dest.name,
                      country: dest.country,
                    })
                  }
                  activeOpacity={0.88}
                >
                  <Image source={{ uri: dest.img }} style={styles.destImage} resizeMode="cover" />
                  <LinearGradient
                    colors={['transparent', 'rgba(0,0,0,0.75)']}
                    style={StyleSheet.absoluteFillObject}
                  />
                  {/* Tag badge */}
                  <View style={styles.destTag}>
                    <Text style={styles.destTagText}>{dest.tag}</Text>
                  </View>
                  <View style={styles.destBottom}>
                    <Text style={styles.destEmoji}>{dest.emoji}</Text>
                    <Text style={styles.destName}>{dest.name}</Text>
                    <Text style={styles.destCountry}>{dest.country}</Text>
                  </View>
                  {/* Tap arrow */}
                  <View style={styles.destArrow}>
                    <Ionicons name="arrow-forward" size={12} color={COLORS.white} />
                  </View>
                </TouchableOpacity>
              ))}
            </ScrollView>
          </View>

          {/* ─── HOW IT WORKS ─────────────────────────────────── */}
          <View style={styles.howSection}>
            <View style={styles.sectionHeader}>
              <Text style={styles.sectionTitle}>How It Works</Text>
            </View>
            <View style={styles.howRow}>
              {HOW_IT_WORKS.map((item, i) => (
                <View key={item.step} style={styles.howItem}>
                  <View style={styles.howIconWrap}>
                    <Ionicons name={item.icon} size={22} color={COLORS.secondary} />
                    <View style={styles.howStepBadge}>
                      <Text style={styles.howStepText}>{item.step}</Text>
                    </View>
                  </View>
                  {i < HOW_IT_WORKS.length - 1 && <View style={styles.howConnector} />}
                  <Text style={styles.howTitle}>{item.title}</Text>
                  <Text style={styles.howDesc}>{item.desc}</Text>
                </View>
              ))}
            </View>
          </View>

          {/* ─── MEMBERSHIP BANNER ────────────────────────────── */}
          {!user?.membership && (
            <TouchableOpacity
              style={styles.membershipBanner}
              onPress={() => navigation.navigate('Plans')}
              activeOpacity={0.88}
            >
              <LinearGradient
                colors={['#2D1B69', '#4A2BA6']}
                start={{ x: 0, y: 0 }}
                end={{ x: 1, y: 1 }}
                style={styles.membershipGradient}
              >
                <View style={styles.membershipLeft}>
                  <View style={styles.membershipIconWrap}>
                    <Ionicons name="diamond" size={22} color={COLORS.accent} />
                  </View>
                  <View style={styles.membershipText}>
                    <Text style={styles.membershipTitle}>Unlock Concierge Access</Text>
                    <Text style={styles.membershipSub}>From €29/month · Cancel anytime</Text>
                  </View>
                </View>
                <View style={styles.membershipArrow}>
                  <Ionicons name="arrow-forward" size={16} color={COLORS.accent} />
                </View>
              </LinearGradient>
            </TouchableOpacity>
          )}

          {/* ─── CURATED PACKAGES ─────────────────────────────── */}
          <View style={styles.section}>
            <View style={styles.sectionHeader}>
              <Text style={styles.sectionTitle}>Curated for You</Text>
              <TouchableOpacity onPress={() => (navigation as any).navigate('Trips')}>
                <Text style={styles.seeAll}>My Trips →</Text>
              </TouchableOpacity>
            </View>

            {loading ? (
              <View style={styles.loadingWrap}>
                <ActivityIndicator size="large" color={COLORS.secondary} />
                <Text style={styles.loadingText}>Loading packages…</Text>
              </View>
            ) : packages.length === 0 ? (
              <View style={styles.emptyWrap}>
                <View style={styles.emptyIcon}>
                  <Ionicons name="globe-outline" size={32} color={COLORS.secondary} />
                </View>
                <Text style={styles.emptyTitle}>Packages Coming Soon</Text>
                <Text style={styles.emptyText}>
                  Our team is curating exclusive trips for you. Check back soon or request your own.
                </Text>
                <TouchableOpacity
                  style={styles.emptyBtn}
                  onPress={() => navigation.navigate('GeneratePackage')}
                >
                  <Text style={styles.emptyBtnText}>Request a Custom Trip</Text>
                </TouchableOpacity>
              </View>
            ) : (
              packages.map((pkg) => (
                <PackageCard
                  key={pkg.id}
                  package={pkg}
                  onPress={() => navigation.navigate('PackageDetail', { packageId: pkg.id })}
                />
              ))
            )}
          </View>

          {/* ─── BOTTOM SPACER ────────────────────────────────── */}
          <View style={{ height: 100 }} />
        </ScrollView>
      </Animated.View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },

  // ─── HERO ───────────────────────────────────────────────────
  heroContainer: {
    height: height * 0.58,
    position: 'relative',
    justifyContent: 'space-between',
  },
  heroBg: { ...StyleSheet.absoluteFillObject, width: '100%', height: '100%' },

  heroHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.xxl + 12,
  },
  greeting: { color: 'rgba(255,255,255,0.7)', fontSize: FONTS.sizes.sm },
  userName: { color: COLORS.white, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  notifBtn: {
    width: 42,
    height: 42,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(255,255,255,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  notifDot: {
    position: 'absolute',
    top: 8,
    right: 8,
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: COLORS.accent,
    borderWidth: 1.5,
    borderColor: COLORS.background,
  },

  heroBody: { paddingHorizontal: SPACING.lg, paddingBottom: SPACING.sm },
  heroBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
    backgroundColor: 'rgba(245,166,35,0.18)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm + 2,
    paddingVertical: 4,
    alignSelf: 'flex-start',
    borderWidth: 1,
    borderColor: 'rgba(245,166,35,0.4)',
    marginBottom: SPACING.sm,
  },
  heroBadgeText: { color: COLORS.accent, fontSize: FONTS.sizes.xs, fontWeight: '700' },
  heroTitle: {
    color: COLORS.white,
    fontSize: 32,
    fontWeight: '800',
    lineHeight: 40,
    marginBottom: SPACING.sm,
  },
  heroSubtitle: {
    color: 'rgba(255,255,255,0.65)',
    fontSize: FONTS.sizes.md,
    lineHeight: 22,
    marginBottom: SPACING.lg,
  },

  heroCTARow: { flexDirection: 'row', gap: SPACING.sm },
  heroPrimaryBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.xs,
    backgroundColor: COLORS.accent,
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.sm + 2,
    ...SHADOWS.md,
  },
  heroPrimaryBtnText: { color: COLORS.primary, fontWeight: '800', fontSize: FONTS.sizes.sm },
  heroSecondaryBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.xs,
    backgroundColor: 'rgba(255,255,255,0.15)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.sm + 2,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.25)',
  },
  heroSecondaryBtnText: { color: COLORS.white, fontWeight: '700', fontSize: FONTS.sizes.sm },

  statsBar: {
    flexDirection: 'row',
    backgroundColor: 'rgba(255,255,255,0.07)',
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.1)',
    paddingVertical: SPACING.md,
    paddingHorizontal: SPACING.xl,
    justifyContent: 'space-around',
  },
  statsDivider: { width: 1, backgroundColor: 'rgba(255,255,255,0.15)' },
  statItem: { alignItems: 'center', flex: 1 },
  statValue: { color: COLORS.white, fontSize: FONTS.sizes.lg, fontWeight: '800' },
  statLabel: { color: 'rgba(255,255,255,0.5)', fontSize: FONTS.sizes.xs, marginTop: 2 },

  // ─── SECTIONS ───────────────────────────────────────────────
  section: { marginBottom: SPACING.lg, paddingTop: SPACING.lg },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: SPACING.lg,
    marginBottom: SPACING.md,
  },
  sectionTitle: { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '700' },
  sectionHint: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
  seeAll: { color: COLORS.secondary, fontSize: FONTS.sizes.sm, fontWeight: '700' },

  // ─── DESTINATIONS ───────────────────────────────────────────
  destRow: { paddingHorizontal: SPACING.lg, gap: SPACING.sm, paddingRight: SPACING.xl },
  destCard: {
    width: 140,
    height: 190,
    borderRadius: RADIUS.xl,
    overflow: 'hidden',
    ...SHADOWS.md,
  },
  destImage: { ...StyleSheet.absoluteFillObject, width: '100%', height: '100%' },
  destTag: {
    position: 'absolute',
    top: SPACING.sm,
    left: SPACING.sm,
    backgroundColor: 'rgba(108,60,225,0.85)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm,
    paddingVertical: 3,
  },
  destTagText: { color: COLORS.white, fontSize: 9, fontWeight: '800', letterSpacing: 0.5 },
  destBottom: {
    position: 'absolute',
    bottom: SPACING.sm,
    left: SPACING.sm,
    right: SPACING.sm,
  },
  destEmoji: { fontSize: 18, marginBottom: 2 },
  destName: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight: '800' },
  destCountry: { color: 'rgba(255,255,255,0.65)', fontSize: FONTS.sizes.xs, marginTop: 1 },
  destArrow: {
    position: 'absolute',
    top: SPACING.sm,
    right: SPACING.sm,
    width: 24,
    height: 24,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(255,255,255,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },

  // ─── HOW IT WORKS ───────────────────────────────────────────
  howSection: { paddingHorizontal: SPACING.lg, marginBottom: SPACING.lg },
  howRow: { flexDirection: 'row', gap: SPACING.xs },
  howItem: { flex: 1, alignItems: 'center' },
  howIconWrap: {
    width: 52,
    height: 52,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(108,60,225,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1.5,
    borderColor: 'rgba(108,60,225,0.3)',
    marginBottom: SPACING.sm,
    position: 'relative',
  },
  howStepBadge: {
    position: 'absolute',
    bottom: -4,
    right: -4,
    backgroundColor: COLORS.secondary,
    borderRadius: RADIUS.full,
    width: 18,
    height: 18,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1.5,
    borderColor: COLORS.background,
  },
  howStepText: { color: COLORS.white, fontSize: 8, fontWeight: '800' },
  howConnector: {
    position: 'absolute',
    top: 26,
    right: -SPACING.xs / 2 - (width / 3 - 68) / 2,
    width: (width / 3 - 52) / 2,
    height: 1.5,
    backgroundColor: 'rgba(108,60,225,0.25)',
  },
  howTitle: {
    color: COLORS.text,
    fontSize: FONTS.sizes.sm,
    fontWeight: '700',
    textAlign: 'center',
    marginBottom: 3,
  },
  howDesc: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.xs,
    textAlign: 'center',
    lineHeight: 16,
  },

  // ─── MEMBERSHIP ─────────────────────────────────────────────
  membershipBanner: {
    marginHorizontal: SPACING.lg,
    marginBottom: SPACING.lg,
    borderRadius: RADIUS.xl,
    overflow: 'hidden',
    ...SHADOWS.lg,
  },
  membershipGradient: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: SPACING.md + 2,
  },
  membershipLeft: { flexDirection: 'row', alignItems: 'center', gap: SPACING.md, flex: 1 },
  membershipIconWrap: {
    width: 48,
    height: 48,
    borderRadius: RADIUS.md,
    backgroundColor: 'rgba(245,166,35,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: 'rgba(245,166,35,0.3)',
  },
  membershipText: { flex: 1 },
  membershipTitle: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight: '700' },
  membershipSub: { color: 'rgba(255,255,255,0.6)', fontSize: FONTS.sizes.xs, marginTop: 2 },
  membershipArrow: {
    width: 32,
    height: 32,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(245,166,35,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },

  // ─── LOADING / EMPTY ────────────────────────────────────────
  loadingWrap: { alignItems: 'center', paddingVertical: SPACING.xxxl, gap: SPACING.md },
  loadingText: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm },
  emptyWrap: {
    alignItems: 'center',
    marginHorizontal: SPACING.lg,
    paddingVertical: SPACING.xxl,
    backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: SPACING.xl,
  },
  emptyIcon: {
    width: 64,
    height: 64,
    borderRadius: RADIUS.full,
    backgroundColor: 'rgba(108,60,225,0.12)',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: SPACING.md,
  },
  emptyTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700', marginBottom: SPACING.xs },
  emptyText: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.sm,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: SPACING.lg,
  },
  emptyBtn: {
    backgroundColor: COLORS.secondary,
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.sm + 2,
  },
  emptyBtnText: { color: COLORS.white, fontWeight: '700', fontSize: FONTS.sizes.sm },
});
