import React, { useEffect, useState, useCallback } from 'react';
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
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { PackageCard } from '../../components/PackageCard';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI, subscriptionAPI } from '../../services/api';

const { width } = Dimensions.get('window');

const FEATURED_DESTINATIONS = [
  { name: 'London', country: 'UK', emoji: '🇬🇧', img: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=400' },
  { name: 'Tokyo', country: 'Japan', emoji: '🇯🇵', img: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=400' },
  { name: 'Paris', country: 'France', emoji: '🇫🇷', img: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=400' },
  { name: 'Dubai', country: 'UAE', emoji: '🇦🇪', img: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=400' },
  { name: 'Bali', country: 'Indonesia', emoji: '🇮🇩', img: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=400' },
  { name: 'Rome', country: 'Italy', emoji: '🇮🇹', img: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=400' },
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
};

const dealToPackage = (deal: any) => ({
  id: String(deal.id),
  destination: deal.location || deal.title,
  country: deal.location || '',
  startDate: deal.start_date || '',
  endDate: deal.end_date || '',
  duration: deal.start_date && deal.end_date
    ? Math.max(1, Math.ceil((new Date(deal.end_date).getTime() - new Date(deal.start_date).getTime()) / 86400000))
    : 7,
  coverImage: deal.image_url || DEST_IMAGES[deal.location] || DEST_IMAGES[deal.title] || 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=800',
  price: deal.price,
  rating: deal.rating || 4.5,
  reviewCount: Math.floor(Math.random() * 300 + 50),
  badge: deal.badge || undefined,
  isAIGenerated: false,
  summary: deal.description || '',
  itinerary: [],
  included: deal.activities ? deal.activities.split(',').map((a: string) => a.trim()) : [],
  highlights: [],
});

export const HomeScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { user, setMembership } = useStore();
  const [refreshing, setRefreshing] = useState(false);
  const [packages, setPackages] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

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

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />
      <ScrollView
        showsVerticalScrollIndicator={false}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={COLORS.secondary} />}
      >
        {/* Header */}
        <View style={styles.header}>
          <View style={styles.headerLeft}>
            <Text style={styles.greeting}>{greeting()},</Text>
            <Text style={styles.userName}>{user?.name?.split(' ')[0] || 'Explorer'} ✦</Text>
          </View>
          <TouchableOpacity style={styles.notifBtn}>
            <Ionicons name="notifications-outline" size={22} color={COLORS.text} />
            <View style={styles.notifDot} />
          </TouchableOpacity>
        </View>

        {/* Hero Banner */}
        <TouchableOpacity
          style={styles.heroBanner}
          onPress={() => navigation.navigate('GeneratePackage')}
          activeOpacity={0.9}
        >
          <Image
            source={{ uri: 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=800' }}
            style={styles.heroImage}
            resizeMode="cover"
          />
          <View style={styles.heroOverlay} />
          <View style={styles.heroContent}>
            <View style={styles.aiBadge}>
              <Ionicons name="sparkles" size={14} color={COLORS.accent} />
              <Text style={styles.aiBadgeText}>AI Powered</Text>
            </View>
            <Text style={styles.heroTitle}>Generate Your{'\n'}Perfect Trip</Text>
            <Text style={styles.heroSubtitle}>Pick a destination & dates — we'll craft the rest</Text>
            <View style={styles.heroBtn}>
              <Text style={styles.heroBtnText}>Try it now</Text>
              <Ionicons name="arrow-forward" size={14} color={COLORS.primary} />
            </View>
          </View>
        </TouchableOpacity>

        {/* Destinations Row */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>Top Destinations</Text>
          </View>
          <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.destRow}>
            {FEATURED_DESTINATIONS.map((dest) => (
              <TouchableOpacity
                key={dest.name}
                style={styles.destCard}
                onPress={() => navigation.navigate('GeneratePackage')}
                activeOpacity={0.85}
              >
                <Image source={{ uri: dest.img }} style={styles.destImage} resizeMode="cover" />
                <View style={styles.destOverlay} />
                <Text style={styles.destEmoji}>{dest.emoji}</Text>
                <Text style={styles.destName}>{dest.name}</Text>
              </TouchableOpacity>
            ))}
          </ScrollView>
        </View>

        {/* Membership Banner */}
        {!user?.membership && (
          <TouchableOpacity
            style={styles.membershipBanner}
            onPress={() => navigation.navigate('Plans')}
            activeOpacity={0.9}
          >
            <View style={styles.membershipLeft}>
              <View style={styles.membershipIcon}>
                <Ionicons name="diamond-outline" size={20} color={COLORS.accent} />
              </View>
              <View>
                <Text style={styles.membershipTitle}>Unlock All Packages</Text>
                <Text style={styles.membershipSub}>From €29/month — cancel anytime</Text>
              </View>
            </View>
            <Ionicons name="chevron-forward" size={18} color={COLORS.accent} />
          </TouchableOpacity>
        )}

        {/* Featured Packages */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>Curated for You</Text>
            <TouchableOpacity onPress={() => (navigation as any).navigate('Main', { screen: 'Explore' })}>
              <Text style={styles.seeAll}>See all</Text>
            </TouchableOpacity>
          </View>
          {loading ? (
            <ActivityIndicator size="large" color={COLORS.secondary} style={{ marginTop: SPACING.xl }} />
          ) : packages.length === 0 ? (
            <Text style={styles.emptyText}>No packages available yet. Check back soon!</Text>
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

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md,
  },
  headerLeft: {},
  greeting: { color: COLORS.textMuted, fontSize: FONTS.sizes.md },
  userName: { color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  notifBtn: {
    width: 44, height: 44, borderRadius: RADIUS.full,
    backgroundColor: COLORS.surface, alignItems: 'center', justifyContent: 'center',
  },
  notifDot: {
    position: 'absolute', top: 10, right: 10,
    width: 8, height: 8, borderRadius: 4,
    backgroundColor: COLORS.accent, borderWidth: 1.5, borderColor: COLORS.background,
  },
  heroBanner: {
    marginHorizontal: SPACING.lg, borderRadius: RADIUS.xl, overflow: 'hidden',
    height: 200, marginBottom: SPACING.lg, ...SHADOWS.lg,
  },
  heroImage: { ...StyleSheet.absoluteFillObject, width: '100%', height: '100%' },
  heroOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(13,10,30,0.55)' },
  heroContent: { flex: 1, padding: SPACING.lg, justifyContent: 'flex-end' },
  aiBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(108,60,225,0.7)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
    alignSelf: 'flex-start', marginBottom: SPACING.sm,
  },
  aiBadgeText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '700' },
  heroTitle: { color: COLORS.white, fontSize: FONTS.sizes.xxl, fontWeight: '800', lineHeight: 32, marginBottom: SPACING.xs },
  heroSubtitle: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, marginBottom: SPACING.md },
  heroBtn: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.xs,
    backgroundColor: COLORS.accent, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.xs + 2, alignSelf: 'flex-start',
  },
  heroBtnText: { color: COLORS.primary, fontWeight: '700', fontSize: FONTS.sizes.sm },
  section: { marginBottom: SPACING.lg },
  sectionHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    paddingHorizontal: SPACING.lg, marginBottom: SPACING.md,
  },
  sectionTitle: { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '700' },
  seeAll: { color: COLORS.secondary, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  destRow: { paddingHorizontal: SPACING.lg, gap: SPACING.sm },
  destCard: { width: 100, height: 130, borderRadius: RADIUS.xl, overflow: 'hidden', ...SHADOWS.sm },
  destImage: { ...StyleSheet.absoluteFillObject, width: '100%', height: '100%' },
  destOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.3)' },
  destEmoji: { position: 'absolute', top: SPACING.sm, left: SPACING.sm, fontSize: 20 },
  destName: { position: 'absolute', bottom: SPACING.sm, left: SPACING.sm, right: SPACING.sm, color: COLORS.white, fontSize: FONTS.sizes.sm, fontWeight: '700' },
  membershipBanner: {
    marginHorizontal: SPACING.lg, marginBottom: SPACING.lg,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, padding: SPACING.md,
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    borderWidth: 1, borderColor: 'rgba(245,166,35,0.3)',
  },
  membershipLeft: { flexDirection: 'row', alignItems: 'center', gap: SPACING.md },
  membershipIcon: {
    width: 44, height: 44, borderRadius: RADIUS.md,
    backgroundColor: 'rgba(245,166,35,0.15)', alignItems: 'center', justifyContent: 'center',
  },
  membershipTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700' },
  membershipSub: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },
  emptyText: { color: COLORS.textMuted, fontSize: FONTS.sizes.md, textAlign: 'center', marginTop: SPACING.xl, paddingHorizontal: SPACING.lg },
});
