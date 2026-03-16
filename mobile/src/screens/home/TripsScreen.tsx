import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Image,
  ActivityIndicator,
  Alert,
  RefreshControl,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { bookingsAPI } from '../../services/api';

const DEST_IMAGES: Record<string, string> = {
  London: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=400',
  Tokyo: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=400',
  Paris: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=400',
  Dubai: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=400',
  Bali: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=400',
  Rome: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=400',
  default: 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=400',
};

const STATUS_COLORS: Record<string, string> = {
  confirmed: '#4CAF50',
  pending: '#F5A623',
  cancelled: '#F44336',
  active: '#4CAF50',
};

export const TripsScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { myBookings, setMyBookings, savedPackages } = useStore();
  const [tab, setTab] = useState<'upcoming' | 'saved'>('upcoming');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [cancelling, setCancelling] = useState<number | null>(null);

  const loadBookings = useCallback(async () => {
    try {
      const res = await bookingsAPI.getMyBookings();
      const bookings = Array.isArray(res.data) ? res.data : [];
      setMyBookings(bookings);
    } catch {
      setMyBookings([]);
    } finally {
      setLoading(false);
    }
  }, [setMyBookings]);

  useEffect(() => { loadBookings(); }, [loadBookings]);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadBookings();
    setRefreshing(false);
  };

  const handleCancel = (bookingId: number) => {
    Alert.alert(
      'Cancel Booking',
      'Are you sure you want to cancel this booking?',
      [
        { text: 'Keep', style: 'cancel' },
        {
          text: 'Cancel Booking',
          style: 'destructive',
          onPress: async () => {
            setCancelling(bookingId);
            try {
              await bookingsAPI.cancel(bookingId);
              await loadBookings();
              Alert.alert('Booking Cancelled', 'Your booking has been cancelled.');
            } catch {
              Alert.alert('Error', 'Could not cancel booking. Please try again.');
            } finally {
              setCancelling(null);
            }
          },
        },
      ]
    );
  };

  const activeBookings = myBookings.filter((b) => !b.cancelled_at);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <Text style={styles.title}>My Trips</Text>
      </View>

      <View style={styles.tabs}>
        <TouchableOpacity
          style={[styles.tab, tab === 'upcoming' && styles.tabActive]}
          onPress={() => setTab('upcoming')}
        >
          <Text style={[styles.tabText, tab === 'upcoming' && styles.tabTextActive]}>
            Upcoming ({activeBookings.length})
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, tab === 'saved' && styles.tabActive]}
          onPress={() => setTab('saved')}
        >
          <Text style={[styles.tabText, tab === 'saved' && styles.tabTextActive]}>
            Saved ({savedPackages.length})
          </Text>
        </TouchableOpacity>
      </View>

      <ScrollView
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.scroll}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={COLORS.secondary} />}
      >
        {tab === 'upcoming' ? (
          loading ? (
            <ActivityIndicator size="large" color={COLORS.secondary} style={{ marginTop: SPACING.xxxl }} />
          ) : activeBookings.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyEmoji}>🧳</Text>
              <Text style={styles.emptyTitle}>No upcoming trips yet</Text>
              <Text style={styles.emptySubtitle}>Book a package to see your upcoming trips here</Text>
              <TouchableOpacity style={styles.emptyBtn} onPress={() => navigation.navigate('GeneratePackage')}>
                <Text style={styles.emptyBtnText}>Generate a Package</Text>
              </TouchableOpacity>
            </View>
          ) : (
            myBookings.map((booking) => (
              <View key={booking.id} style={styles.tripCard}>
                <Image
                  source={{ uri: DEST_IMAGES[booking.destination] || DEST_IMAGES.default }}
                  style={styles.tripImage}
                  resizeMode="cover"
                />
                <View style={styles.tripInfo}>
                  <View style={styles.tripHeader}>
                    <Text style={styles.tripDest}>{booking.destination || `Booking #${booking.id}`}</Text>
                    <View style={[styles.statusBadge, { backgroundColor: (booking.cancelled_at ? STATUS_COLORS.cancelled : STATUS_COLORS.confirmed) + '20' }]}>
                      <Text style={[styles.statusText, { color: booking.cancelled_at ? STATUS_COLORS.cancelled : STATUS_COLORS.confirmed }]}>
                        {booking.cancelled_at ? 'cancelled' : 'confirmed'}
                      </Text>
                    </View>
                  </View>
                  {booking.start_date ? (
                    <View style={styles.tripMeta}>
                      <Ionicons name="calendar-outline" size={12} color={COLORS.textMuted} />
                      <Text style={styles.tripDate}>
                        {booking.start_date} → {booking.end_date}
                      </Text>
                    </View>
                  ) : null}
                  <View style={styles.tripFooter}>
                    <Text style={styles.tripPrice}>Booking #{booking.id}</Text>
                    {!booking.cancelled_at && (
                      <TouchableOpacity
                        style={styles.cancelBtn}
                        onPress={() => handleCancel(booking.id)}
                        disabled={cancelling === booking.id}
                      >
                        {cancelling === booking.id ? (
                          <ActivityIndicator size="small" color={COLORS.error} />
                        ) : (
                          <Text style={styles.cancelBtnText}>Cancel</Text>
                        )}
                      </TouchableOpacity>
                    )}
                  </View>
                </View>
              </View>
            ))
          )
        ) : (
          savedPackages.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyEmoji}>💫</Text>
              <Text style={styles.emptyTitle}>No saved packages yet</Text>
              <Text style={styles.emptySubtitle}>Save packages you love to compare later</Text>
              <TouchableOpacity style={styles.emptyBtn} onPress={() => (navigation as any).navigate('Main', { screen: 'Explore' })}>
                <Text style={styles.emptyBtnText}>Explore Packages</Text>
              </TouchableOpacity>
            </View>
          ) : (
            savedPackages.map((pkg) => (
              <TouchableOpacity
                key={pkg.id}
                style={styles.tripCard}
                onPress={() => navigation.navigate('PackageDetail', { packageId: pkg.id })}
                activeOpacity={0.85}
              >
                <Image
                  source={{ uri: DEST_IMAGES[pkg.destination] || DEST_IMAGES.default }}
                  style={styles.tripImage}
                  resizeMode="cover"
                />
                <View style={styles.tripInfo}>
                  <View style={styles.tripHeader}>
                    <Text style={styles.tripDest}>{pkg.destination}</Text>
                    <Text style={styles.tripPrice}>€{pkg.price.toLocaleString()}</Text>
                  </View>
                  {pkg.startDate ? (
                    <View style={styles.tripMeta}>
                      <Ionicons name="calendar-outline" size={12} color={COLORS.textMuted} />
                      <Text style={styles.tripDate}>{pkg.startDate} → {pkg.endDate}</Text>
                    </View>
                  ) : null}
                  <View style={styles.tripMeta}>
                    <Ionicons name="time-outline" size={12} color={COLORS.textMuted} />
                    <Text style={styles.tripDate}>{pkg.duration} days</Text>
                  </View>
                </View>
              </TouchableOpacity>
            ))
          )
        )}
        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: { paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md },
  title: { color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  tabs: {
    flexDirection: 'row', marginHorizontal: SPACING.lg,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    padding: 3, marginBottom: SPACING.lg,
  },
  tab: { flex: 1, paddingVertical: SPACING.sm, alignItems: 'center', borderRadius: RADIUS.md },
  tabActive: { backgroundColor: COLORS.secondary },
  tabText: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  tabTextActive: { color: COLORS.white },
  scroll: { paddingHorizontal: SPACING.lg },
  empty: { alignItems: 'center', paddingTop: SPACING.xxxl },
  emptyEmoji: { fontSize: 64, marginBottom: SPACING.lg },
  emptyTitle: { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '700', marginBottom: SPACING.sm, textAlign: 'center' },
  emptySubtitle: { color: COLORS.textMuted, fontSize: FONTS.sizes.md, textAlign: 'center', lineHeight: 22, marginBottom: SPACING.xl },
  emptyBtn: {
    backgroundColor: COLORS.secondary, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.xl, paddingVertical: SPACING.md,
  },
  emptyBtnText: { color: COLORS.white, fontWeight: '700', fontSize: FONTS.sizes.md },
  tripCard: {
    flexDirection: 'row', backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl, overflow: 'hidden', marginBottom: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  tripImage: { width: 90, height: 110 },
  tripInfo: { flex: 1, padding: SPACING.md },
  tripHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.xs },
  tripDest: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700', flex: 1 },
  tripPrice: { color: COLORS.accent, fontSize: FONTS.sizes.md, fontWeight: '700' },
  statusBadge: { borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical: 2 },
  statusText: { fontSize: FONTS.sizes.xs, fontWeight: '600', textTransform: 'capitalize' },
  tripMeta: { flexDirection: 'row', alignItems: 'center', gap: 4, marginBottom: 3 },
  tripDate: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
  tripFooter: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: SPACING.xs },
  cancelBtn: {
    borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical: 3,
    borderWidth: 1, borderColor: 'rgba(244,67,54,0.3)',
  },
  cancelBtnText: { color: COLORS.error, fontSize: FONTS.sizes.xs, fontWeight: '600' },
});
