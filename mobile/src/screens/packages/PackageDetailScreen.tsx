import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Image,
  Dimensions,
  StatusBar,
  ActivityIndicator,
  Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation, useRoute, RouteProp } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { packagesAPI, bookingsAPI } from '../../services/api';

const { width, height } = Dimensions.get('window');

const DEST_IMAGES: Record<string, string> = {
  London: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=800',
  Tokyo: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=800',
  Paris: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=800',
  Dubai: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=800',
  Bali: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=800',
  Rome: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=800',
  Santorini: 'https://images.unsplash.com/photo-1570077188670-e3a8d69ac5ff?w=800',
  Barcelona: 'https://images.unsplash.com/photo-1558642452-9d2a7deb7f62?w=800',
  default: 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=800',
};

const safeParseJSON = (raw: any, fallback: any) => {
  if (!raw || raw === 'null') return fallback;
  if (typeof raw !== 'string') return raw;
  try { return JSON.parse(raw); } catch { return fallback; }
};

const normalizePkg = (data: any, isDeal: boolean) => {
  if (isDeal) {
    const loc = data.location || data.title || '';
    const country = data.country || loc;
    const itinerary = safeParseJSON(data.itinerary_json, []);
    const flight = safeParseJSON(data.flight_json, null);
    const hotel = safeParseJSON(data.hotel_json, null);
    const highlights = safeParseJSON(data.highlights_json, []);
    const included = safeParseJSON(data.included_json, null);
    const duration = data.duration ||
      (data.start_date && data.end_date
        ? Math.max(1, Math.ceil((new Date(data.end_date).getTime() - new Date(data.start_date).getTime()) / 86400000))
        : 7);
    return {
      id: String(data.id),
      destination: loc,
      country,
      startDate: data.start_date || '',
      endDate: data.end_date || '',
      duration,
      coverImage: data.image_url || DEST_IMAGES[loc] || DEST_IMAGES.default,
      price: data.price,
      originalPrice: undefined,
      rating: data.rating || 4.5,
      reviewCount: data.review_count || 120,
      badge: data.badge || undefined,
      isAIGenerated: false,
      summary: data.summary || data.description || '',
      included: included || (data.activities ? data.activities.split(',').map((a: string) => a.trim()) : ['Flights', 'Hotel', 'Activities']),
      highlights: highlights.length > 0 ? highlights : (data.activities ? data.activities.split(',').map((a: string) => a.trim()) : []),
      itinerary,
      flight,
      hotel,
    };
  }
  // AI generated package
  return {
    id: String(data.id),
    destination: data.destination,
    country: data.destination,
    startDate: data.start_date || data.startDate || '',
    endDate: data.end_date || data.endDate || '',
    duration: data.duration,
    coverImage: DEST_IMAGES[data.destination] || DEST_IMAGES.default,
    price: data.price,
    originalPrice: undefined,
    rating: data.rating || 4.8,
    reviewCount: data.reviewCount || 0,
    badge: data.badge || 'AI Curated',
    isAIGenerated: true,
    summary: data.summary || `A personalized ${data.duration}-day ${data.destination} experience crafted for you.`,
    included: data.included || ['Flights', 'Hotel', 'Restaurant Reservations', 'Experience Tickets'],
    highlights: data.highlights || [],
    itinerary: data.itinerary || [],
    flight: data.flight || data.flight_info,
    hotel: data.hotel || data.hotel_info,
  };
};

export const PackageDetailScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const route = useRoute<RouteProp<RootStackParamList, 'PackageDetail'>>();
  const { savedPackages, savePackage, unsavePackage, user, addTrip } = useStore();
  const [activeTab, setActiveTab] = useState<'overview' | 'itinerary' | 'details'>('overview');
  const [pkg, setPkg] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [booking, setBooking] = useState(false);

  const { packageId } = route.params;
  const isGeneratedId = !isNaN(Number(packageId)) && Number(packageId) > 1000;

  const loadPackage = useCallback(async () => {
    try {
      // Try generated package endpoint first (numeric IDs from AI generation are typically higher)
      // Try deal endpoint first, then generated package endpoint
      let data: any = null;
      let isDeal = false;

      try {
        const res = await packagesAPI.getById(packageId);
        data = res.data;
        isDeal = true;
      } catch {
        // Not a deal, try generated package
        try {
          const res = await packagesAPI.getGenerated(packageId);
          data = res.data;
          isDeal = false;
        } catch {
          data = null;
        }
      }

      if (data) {
        setPkg(normalizePkg(data, isDeal));
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [packageId]);

  useEffect(() => { loadPackage(); }, [loadPackage]);

  const isSaved = savedPackages.some((p) => p.id === packageId);
  const hasMembership = !!user?.membership;

  const handleBooking = async () => {
    if (!pkg) return;
    if (!hasMembership) {
      navigation.navigate('Plans');
      return;
    }
    setBooking(true);
    try {
      await bookingsAPI.create({
        deal_id: Number(pkg.id),
        destination: pkg.destination,
        start_date: pkg.startDate || new Date().toISOString().split('T')[0],
        end_date: pkg.endDate || new Date(Date.now() + pkg.duration * 86400000).toISOString().split('T')[0],
        guests: 1,
      });
      addTrip(pkg);
      Alert.alert(
        '✦ Booking Confirmed!',
        `Your trip to ${pkg.destination} has been booked successfully.`,
        [{ text: 'View My Trips', onPress: () => navigation.navigate('Main') }]
      );
    } catch (err: any) {
      const msg = err?.response?.data?.error || 'Could not complete booking. Please try again.';
      Alert.alert('Booking Failed', msg);
    } finally {
      setBooking(false);
    }
  };

  if (loading) {
    return (
      <View style={[styles.container, { justifyContent: 'center', alignItems: 'center' }]}>
        <ActivityIndicator size="large" color={COLORS.secondary} />
        <Text style={{ color: COLORS.textMuted, marginTop: SPACING.md }}>Loading package...</Text>
      </View>
    );
  }

  if (!pkg) {
    return (
      <View style={[styles.container, { justifyContent: 'center', alignItems: 'center' }]}>
        <Text style={{ color: COLORS.text, fontSize: FONTS.sizes.xl }}>Package not found</Text>
        <TouchableOpacity style={{ marginTop: SPACING.lg }} onPress={() => navigation.goBack()}>
          <Text style={{ color: COLORS.secondary }}>Go back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <ScrollView showsVerticalScrollIndicator={false} bounces={false}>
        {/* Hero Image */}
        <View style={styles.heroContainer}>
          <Image source={{ uri: pkg.coverImage }} style={styles.heroImage} resizeMode="cover" />
          <View style={styles.heroOverlay} />

          <View style={styles.topButtons}>
            <TouchableOpacity style={styles.iconBtn} onPress={() => navigation.goBack()}>
              <Ionicons name="arrow-back" size={20} color={COLORS.text} />
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.iconBtn}
              onPress={() => isSaved ? unsavePackage(pkg.id) : savePackage(pkg)}
            >
              <Ionicons name={isSaved ? 'heart' : 'heart-outline'} size={20} color={isSaved ? '#FF4B6E' : COLORS.text} />
            </TouchableOpacity>
          </View>

          <View style={styles.heroInfo}>
            {pkg.isAIGenerated && (
              <View style={styles.aiBadge}>
                <Ionicons name="sparkles" size={12} color={COLORS.accent} />
                <Text style={styles.aiBadgeText}>AI Curated</Text>
              </View>
            )}
            {pkg.badge && !pkg.isAIGenerated && (
              <View style={styles.aiBadge}>
                <Text style={styles.aiBadgeText}>{pkg.badge}</Text>
              </View>
            )}
            <Text style={styles.heroTitle}>{pkg.destination}</Text>
            <Text style={styles.heroCountry}>{pkg.country !== pkg.destination ? pkg.country : ''}</Text>
            <View style={styles.heroMeta}>
              <View style={styles.metaPill}>
                <Ionicons name="star" size={12} color={COLORS.accent} />
                <Text style={styles.metaText}>{Number(pkg.rating ?? 4.5).toFixed(1)} ({pkg.reviewCount})</Text>
              </View>
              <View style={styles.metaPill}>
                <Ionicons name="calendar-outline" size={12} color={COLORS.textSecondary} />
                <Text style={styles.metaText}>{pkg.duration} days</Text>
              </View>
            </View>
          </View>
        </View>

        <View style={styles.content}>
          {/* Tabs */}
          <View style={styles.tabs}>
            {(['overview', 'itinerary', 'details'] as const).map((tab) => (
              <TouchableOpacity
                key={tab}
                style={[styles.tab, activeTab === tab && styles.tabActive]}
                onPress={() => setActiveTab(tab)}
              >
                <Text style={[styles.tabText, activeTab === tab && styles.tabTextActive]}>
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </Text>
              </TouchableOpacity>
            ))}
          </View>

          {activeTab === 'overview' && (
            <View>
              <Text style={styles.summary}>{pkg.summary}</Text>

              {pkg.included?.length > 0 && (
                <>
                  <Text style={styles.sectionTitle}>What's Included</Text>
                  <View style={styles.includedList}>
                    {pkg.included.map((item: string, i: number) => (
                      <View key={i} style={styles.includedItem}>
                        <Text style={styles.includedText}>{item}</Text>
                      </View>
                    ))}
                  </View>
                </>
              )}

              {pkg.highlights?.length > 0 && (
                <>
                  <Text style={styles.sectionTitle}>Highlights</Text>
                  {pkg.highlights.map((h: string, i: number) => (
                    <View key={i} style={styles.highlightItem}>
                      <View style={styles.highlightDot} />
                      <Text style={styles.highlightText}>{h}</Text>
                    </View>
                  ))}
                </>
              )}
            </View>
          )}

          {activeTab === 'itinerary' && (
            <View>
              {pkg.itinerary?.length > 0 ? (
                pkg.itinerary.map((day: any, i: number) => (
                  <View key={i} style={styles.dayCard}>
                    <View style={styles.dayHeader}>
                      <View style={styles.dayBadge}>
                        <Text style={styles.dayNumber}>Day {day.day}</Text>
                      </View>
                      <Text style={styles.dayTitle}>{day.title}</Text>
                    </View>
                    {day.description ? <Text style={styles.dayDesc}>{day.description}</Text> : null}
                    {(day.activities || []).map((act: any, j: number) => (
                      <View key={j} style={styles.activityItem}>
                        <View style={styles.activityDot} />
                        <Text style={styles.activityText}>
                          {typeof act === 'string' ? act : act.name || act.description || ''}
                        </Text>
                      </View>
                    ))}
                  </View>
                ))
              ) : (
                <View style={styles.emptyTab}>
                  <Text style={styles.emptyTabText}>
                    {pkg.isAIGenerated
                      ? 'Detailed itinerary is being crafted by our AI'
                      : 'Itinerary details available after booking'}
                  </Text>
                </View>
              )}
            </View>
          )}

          {activeTab === 'details' && (
            <View>
              {pkg.flight ? (
                <>
                  <Text style={styles.sectionTitle}>Flights</Text>
                  <View style={styles.detailCard}>
                    <View style={styles.flightRow}>
                      <Ionicons name="airplane-outline" size={18} color={COLORS.secondary} />
                      <View style={styles.flightInfo}>
                        <Text style={styles.flightAirline}>
                          {pkg.flight.outbound?.airline || 'TBD'} — {pkg.flight.class || 'Economy'}
                        </Text>
                        {pkg.flight.outbound && (
                          <Text style={styles.flightDetails}>
                            Outbound: {pkg.flight.outbound.departure} → {pkg.flight.outbound.arrival}
                            {pkg.flight.outbound.duration ? ` (${pkg.flight.outbound.duration})` : ''}
                          </Text>
                        )}
                        {pkg.flight.return && (
                          <Text style={styles.flightDetails}>
                            Return: {pkg.flight.return.departure} → {pkg.flight.return.arrival}
                            {pkg.flight.return.duration ? ` (${pkg.flight.return.duration})` : ''}
                          </Text>
                        )}
                      </View>
                    </View>
                  </View>
                </>
              ) : null}

              {pkg.hotel ? (
                <>
                  <Text style={styles.sectionTitle}>Accommodation</Text>
                  <View style={styles.detailCard}>
                    <Text style={styles.hotelName}>{pkg.hotel.name}</Text>
                    <Text style={styles.hotelLocation}>
                      {'★'.repeat(Math.min(pkg.hotel.stars || 4, 5))} · {pkg.hotel.location}
                    </Text>
                    <Text style={styles.hotelDesc}>{pkg.hotel.description}</Text>
                    <View style={styles.amenities}>
                      {(pkg.hotel.amenities || []).map((a: string, i: number) => (
                        <View key={i} style={styles.amenityChip}>
                          <Text style={styles.amenityText}>{a}</Text>
                        </View>
                      ))}
                    </View>
                  </View>
                </>
              ) : (
                <View style={styles.emptyTab}>
                  <Text style={styles.emptyTabText}>Accommodation details available after booking</Text>
                </View>
              )}
            </View>
          )}
        </View>

        <View style={{ height: 120 }} />
      </ScrollView>

      {/* Booking Footer */}
      <View style={styles.footer}>
        <View style={styles.priceBlock}>
          {pkg.originalPrice && (
            <Text style={styles.originalPrice}>€{pkg.originalPrice.toLocaleString()}</Text>
          )}
          <Text style={styles.price}>€{pkg.price.toLocaleString()}</Text>
          <Text style={styles.perPerson}>/ person</Text>
        </View>
        <Button
          label={booking ? 'Booking...' : hasMembership ? 'Book Now' : 'Subscribe to Book'}
          onPress={handleBooking}
          loading={booking}
          fullWidth={false}
          style={{ paddingHorizontal: SPACING.xl }}
        />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  heroContainer: { height: height * 0.42, position: 'relative' },
  heroImage: { width: '100%', height: '100%' },
  heroOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.38)' },
  topButtons: {
    position: 'absolute', top: SPACING.xxl, left: SPACING.lg, right: SPACING.lg,
    flexDirection: 'row', justifyContent: 'space-between',
  },
  iconBtn: {
    width: 40, height: 40, borderRadius: RADIUS.full,
    backgroundColor: 'rgba(0,0,0,0.45)', alignItems: 'center', justifyContent: 'center',
  },
  heroInfo: { position: 'absolute', bottom: SPACING.xl, left: SPACING.lg, right: SPACING.lg },
  aiBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(108,60,225,0.7)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
    alignSelf: 'flex-start', marginBottom: SPACING.sm,
  },
  aiBadgeText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '700' },
  heroTitle: { color: COLORS.white, fontSize: FONTS.sizes.xxxl, fontWeight: '800' },
  heroCountry: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, marginBottom: SPACING.sm },
  heroMeta: { flexDirection: 'row', gap: SPACING.sm },
  metaPill: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(0,0,0,0.4)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  metaText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  content: { padding: SPACING.lg },
  tabs: {
    flexDirection: 'row', backgroundColor: COLORS.surface,
    borderRadius: RADIUS.lg, padding: 3, marginBottom: SPACING.lg,
  },
  tab: { flex: 1, paddingVertical: SPACING.sm, alignItems: 'center', borderRadius: RADIUS.md },
  tabActive: { backgroundColor: COLORS.secondary },
  tabText: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  tabTextActive: { color: COLORS.white },
  summary: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, lineHeight: 24, marginBottom: SPACING.lg },
  sectionTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700', marginBottom: SPACING.md, marginTop: SPACING.md },
  includedList: { flexDirection: 'row', flexWrap: 'wrap', gap: SPACING.sm, marginBottom: SPACING.md },
  includedItem: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.xs + 2,
    borderWidth: 1, borderColor: COLORS.border,
  },
  includedText: { color: COLORS.text, fontSize: FONTS.sizes.sm },
  highlightItem: { flexDirection: 'row', alignItems: 'flex-start', gap: SPACING.sm, marginBottom: SPACING.sm },
  highlightDot: { width: 6, height: 6, borderRadius: 3, backgroundColor: COLORS.secondary, marginTop: 7 },
  highlightText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, flex: 1, lineHeight: 22 },
  emptyTab: {
    alignItems: 'center', paddingVertical: SPACING.xxxl,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    borderWidth: 1, borderColor: COLORS.border,
  },
  emptyTabText: { color: COLORS.textMuted, fontSize: FONTS.sizes.md, textAlign: 'center', paddingHorizontal: SPACING.lg },
  dayCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    padding: SPACING.md, marginBottom: SPACING.md, borderWidth: 1, borderColor: COLORS.border,
  },
  dayHeader: { flexDirection: 'row', alignItems: 'center', gap: SPACING.md, marginBottom: SPACING.sm },
  dayBadge: {
    backgroundColor: COLORS.secondary, borderRadius: RADIUS.md,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  dayNumber: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '700' },
  dayTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '600', flex: 1 },
  dayDesc: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 18, marginBottom: SPACING.sm },
  activityItem: { flexDirection: 'row', alignItems: 'flex-start', gap: SPACING.sm, paddingVertical: 3 },
  activityDot: { width: 5, height: 5, borderRadius: 2.5, backgroundColor: COLORS.textMuted, marginTop: 8 },
  activityText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, flex: 1, lineHeight: 20 },
  detailCard: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    padding: SPACING.md, marginBottom: SPACING.md, borderWidth: 1, borderColor: COLORS.border,
  },
  flightRow: { flexDirection: 'row', gap: SPACING.md },
  flightInfo: { flex: 1 },
  flightAirline: { color: COLORS.text, fontWeight: '700', marginBottom: SPACING.xs },
  flightDetails: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 20 },
  hotelName: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  hotelLocation: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, marginTop: 2, marginBottom: SPACING.sm },
  hotelDesc: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, lineHeight: 20, marginBottom: SPACING.md },
  amenities: { flexDirection: 'row', flexWrap: 'wrap', gap: SPACING.xs },
  amenityChip: {
    backgroundColor: COLORS.surfaceLight, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  amenityText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.xs },
  footer: {
    position: 'absolute', bottom: 0, left: 0, right: 0,
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    padding: SPACING.lg, paddingBottom: SPACING.xxl,
    backgroundColor: COLORS.background, borderTopWidth: 1, borderTopColor: COLORS.border,
  },
  priceBlock: { flexDirection: 'row', alignItems: 'baseline', gap: SPACING.xs },
  originalPrice: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, textDecorationLine: 'line-through' },
  price: { color: COLORS.accent, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  perPerson: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
});
