import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Image,
  Dimensions,
  StatusBar,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation, useRoute, RouteProp } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { Button } from '../../components/Button';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../../constants/theme';
import { useStore } from '../../store/useStore';

const { width, height } = Dimensions.get('window');

const MOCK_PACKAGE = {
  id: '1',
  destination: 'London',
  country: 'United Kingdom',
  startDate: '2025-12-20',
  endDate: '2025-12-29',
  duration: 9,
  price: 2890,
  originalPrice: 3400,
  rating: 4.9,
  reviewCount: 342,
  badge: 'Best Seller',
  isAIGenerated: true,
  summary: 'A fully curated 9-day London experience crafted for your love of culture and fine dining. Stay at a boutique hotel in Mayfair with daily itineraries, Michelin-starred restaurant reservations, and private museum tours.',
  coverImage: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=800',
  included: ['✈️ Return Flights', '🏨 Boutique Hotel (Mayfair)', '🍽️ Restaurant Reservations', '🎭 Experience Tickets', '🚕 Airport Transfers'],
  highlights: ['Private Tower of London after-hours tour', 'West End theatre — Hamilton', 'Afternoon tea at Claridge\'s', 'Borough Market food tour', 'Greenwich Observatory visit'],
  itinerary: [
    {
      day: 1,
      title: 'Arrival & Mayfair Welcome',
      activities: ['Check into The Connaught Hotel', 'Evening stroll through Hyde Park', 'Welcome dinner at Sketch'],
    },
    {
      day: 2,
      title: 'Royal London',
      activities: ['Buckingham Palace', 'Westminster Abbey tour', 'Lunch at Dishoom Covent Garden', 'West End: Hamilton evening'],
    },
    {
      day: 3,
      title: 'History & Culture',
      activities: ['Private Tower of London tour', 'Tower Bridge crossing', 'Borough Market lunch', 'Tate Modern gallery'],
    },
    {
      day: 4,
      title: 'East London & Street Art',
      activities: ['Shoreditch food tour', 'Brick Lane market', 'Columbia Road Flower Market', 'Dinner at Brat restaurant'],
    },
    {
      day: 5,
      title: 'Day Trip: Cotswolds',
      activities: ['Private coach to Cotswolds', 'Bourton-on-the-Water walk', 'Traditional pub lunch', 'Return to London'],
    },
  ],
  flight: {
    outbound: { airline: 'British Airways', flightNumber: 'BA123', departure: '09:00', arrival: '11:30', duration: '2h 30m', stops: 0 },
    return: { airline: 'British Airways', flightNumber: 'BA456', departure: '14:00', arrival: '17:30', duration: '2h 30m', stops: 0 },
    class: 'Economy',
  },
  hotel: {
    name: 'The Connaught',
    stars: 5,
    location: 'Mayfair, London',
    description: 'An iconic Mayfair hotel known for its timeless elegance and impeccable service.',
    amenities: ['Spa', 'Fine dining', 'Bar', 'Concierge', 'Fitness center'],
  },
};

export const PackageDetailScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const route = useRoute<RouteProp<RootStackParamList, 'PackageDetail'>>();
  const { savedPackages, savePackage, unsavePackage, user } = useStore();
  const [activeTab, setActiveTab] = useState<'overview' | 'itinerary' | 'details'>('overview');

  const pkg = MOCK_PACKAGE;
  const isSaved = savedPackages.some((p) => p.id === pkg.id);
  const hasMembership = !!user?.membership;

  const handleBooking = () => {
    if (!hasMembership) {
      navigation.navigate('Plans');
    } else {
      navigation.navigate('Payment', { planId: 'one-time', packageId: pkg.id });
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <ScrollView showsVerticalScrollIndicator={false} bounces={false}>
        {/* Hero Image */}
        <View style={styles.heroContainer}>
          <Image
            source={{ uri: pkg.coverImage }}
            style={styles.heroImage}
            resizeMode="cover"
          />
          <View style={styles.heroOverlay} />

          {/* Top Buttons */}
          <View style={styles.topButtons}>
            <TouchableOpacity style={styles.iconBtn} onPress={() => navigation.goBack()}>
              <Ionicons name="arrow-back" size={20} color={COLORS.text} />
            </TouchableOpacity>
            <View style={styles.topRight}>
              <TouchableOpacity
                style={styles.iconBtn}
                onPress={() => isSaved ? unsavePackage(pkg.id) : savePackage(pkg as any)}
              >
                <Ionicons name={isSaved ? 'heart' : 'heart-outline'} size={20} color={isSaved ? '#FF4B6E' : COLORS.text} />
              </TouchableOpacity>
            </View>
          </View>

          {/* Hero Info */}
          <View style={styles.heroInfo}>
            {pkg.isAIGenerated && (
              <View style={styles.aiBadge}>
                <Ionicons name="sparkles" size={12} color={COLORS.accent} />
                <Text style={styles.aiBadgeText}>AI Curated</Text>
              </View>
            )}
            <Text style={styles.heroTitle}>{pkg.destination}</Text>
            <Text style={styles.heroCountry}>{pkg.country}</Text>
            <View style={styles.heroMeta}>
              <View style={styles.ratingPill}>
                <Ionicons name="star" size={12} color={COLORS.accent} />
                <Text style={styles.ratingText}>{pkg.rating} ({pkg.reviewCount})</Text>
              </View>
              <View style={styles.durationPill}>
                <Ionicons name="calendar-outline" size={12} color={COLORS.textSecondary} />
                <Text style={styles.durationText}>{pkg.duration} days</Text>
              </View>
            </View>
          </View>
        </View>

        {/* Content */}
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
              {/* Summary */}
              <Text style={styles.summary}>{pkg.summary}</Text>

              {/* Included */}
              <Text style={styles.sectionTitle}>What's Included</Text>
              <View style={styles.includedList}>
                {pkg.included.map((item, i) => (
                  <View key={i} style={styles.includedItem}>
                    <Text style={styles.includedText}>{item}</Text>
                  </View>
                ))}
              </View>

              {/* Highlights */}
              <Text style={styles.sectionTitle}>Highlights</Text>
              {pkg.highlights.map((h, i) => (
                <View key={i} style={styles.highlightItem}>
                  <View style={styles.highlightDot} />
                  <Text style={styles.highlightText}>{h}</Text>
                </View>
              ))}
            </View>
          )}

          {activeTab === 'itinerary' && (
            <View>
              {pkg.itinerary.map((day, i) => (
                <View key={i} style={styles.dayCard}>
                  <View style={styles.dayHeader}>
                    <View style={styles.dayBadge}>
                      <Text style={styles.dayNumber}>Day {day.day}</Text>
                    </View>
                    <Text style={styles.dayTitle}>{day.title}</Text>
                  </View>
                  {day.activities.map((act, j) => (
                    <View key={j} style={styles.activityItem}>
                      <View style={styles.activityDot} />
                      <Text style={styles.activityText}>{act}</Text>
                    </View>
                  ))}
                </View>
              ))}
            </View>
          )}

          {activeTab === 'details' && (
            <View>
              {/* Flight */}
              <Text style={styles.sectionTitle}>Flights</Text>
              <View style={styles.detailCard}>
                <View style={styles.flightRow}>
                  <Ionicons name="airplane-outline" size={18} color={COLORS.secondary} />
                  <View style={styles.flightInfo}>
                    <Text style={styles.flightAirline}>{pkg.flight.outbound.airline} — {pkg.flight.class}</Text>
                    <Text style={styles.flightDetails}>
                      Outbound: {pkg.flight.outbound.departure} → {pkg.flight.outbound.arrival} ({pkg.flight.outbound.duration})
                    </Text>
                    <Text style={styles.flightDetails}>
                      Return: {pkg.flight.return.departure} → {pkg.flight.return.arrival} ({pkg.flight.return.duration})
                    </Text>
                  </View>
                </View>
              </View>

              {/* Hotel */}
              <Text style={styles.sectionTitle}>Accommodation</Text>
              <View style={styles.detailCard}>
                <View style={styles.hotelHeader}>
                  <View>
                    <Text style={styles.hotelName}>{pkg.hotel.name}</Text>
                    <Text style={styles.hotelLocation}>
                      {'★'.repeat(pkg.hotel.stars)} · {pkg.hotel.location}
                    </Text>
                  </View>
                </View>
                <Text style={styles.hotelDesc}>{pkg.hotel.description}</Text>
                <View style={styles.amenities}>
                  {pkg.hotel.amenities.map((a, i) => (
                    <View key={i} style={styles.amenityChip}>
                      <Text style={styles.amenityText}>{a}</Text>
                    </View>
                  ))}
                </View>
              </View>
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
          label={hasMembership ? 'Book Package' : 'View Plans to Book'}
          onPress={handleBooking}
          fullWidth={false}
          style={{ paddingHorizontal: SPACING.xl }}
        />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  heroContainer: { height: height * 0.45, position: 'relative' },
  heroImage: { width: '100%', height: '100%' },
  heroOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.35)' },
  topButtons: {
    position: 'absolute', top: SPACING.xxl, left: SPACING.lg, right: SPACING.lg,
    flexDirection: 'row', justifyContent: 'space-between',
  },
  iconBtn: {
    width: 40, height: 40, borderRadius: RADIUS.full,
    backgroundColor: 'rgba(0,0,0,0.45)', alignItems: 'center', justifyContent: 'center',
  },
  topRight: { flexDirection: 'row', gap: SPACING.sm },
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
  ratingPill: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(0,0,0,0.4)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  ratingText: { color: COLORS.white, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  durationPill: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(0,0,0,0.4)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 3,
  },
  durationText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.xs },
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
  hotelHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: SPACING.sm },
  hotelName: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  hotelLocation: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, marginTop: 2 },
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
