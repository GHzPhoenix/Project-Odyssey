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
import { useStripe } from '@stripe/stripe-react-native';
import { RootStackParamList, RequestedPackage } from '../../types';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { bookingsAPI, packagesAPI, stripeAPI } from '../../services/api';

const DEST_IMAGES: Record<string, string> = {
  London:    'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=400',
  Tokyo:     'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=400',
  Paris:     'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=400',
  Dubai:     'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=400',
  Bali:      'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=400',
  Rome:      'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=400',
  default:   'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=400',
};

// ─── Status Badge ─────────────────────────────────────────────────────────────

const StatusBadge = ({ status }: { status: string }) => {
  const config: Record<string, { label: string; bg: string; color: string }> = {
    pending:   { label: 'Being crafted ✨',  bg: 'rgba(245,166,35,0.15)',  color: '#F5A623' },
    ready:     { label: 'Ready to pay ✅',   bg: 'rgba(201,168,76,0.18)',  color: '#C9A84C' },
    confirmed: { label: 'Confirmed 🎉',      bg: 'rgba(76,175,80,0.15)',   color: '#4CAF50' },
    active:    { label: 'Active',            bg: 'rgba(76,175,80,0.15)',   color: '#4CAF50' },
    cancelled: { label: 'Cancelled',         bg: 'rgba(244,67,54,0.15)',   color: '#F44336' },
  };
  const c = config[status] || { label: status, bg: 'rgba(255,255,255,0.08)', color: COLORS.textSecondary };
  return (
    <View style={[styles.statusBadge, { backgroundColor: c.bg }]}>
      <Text style={[styles.statusText, { color: c.color }]}>{c.label}</Text>
    </View>
  );
};

// ─── Requested Tab ────────────────────────────────────────────────────────────

const RequestedTab = ({ refreshing, onRefresh }: { refreshing: boolean; onRefresh: () => void }) => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { requestedPackages, setRequestedPackages } = useStore();
  const { initPaymentSheet, presentPaymentSheet } = useStripe();
  const [loading, setLoading]           = useState(true);
  const [paying, setPaying]             = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await packagesAPI.getMyRequests();
      setRequestedPackages(Array.isArray(res.data) ? res.data : []);
    } catch {
      setRequestedPackages([]);
    } finally {
      setLoading(false);
    }
  }, [setRequestedPackages]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (refreshing) load();
  }, [refreshing, load]);

  const handlePayNow = async (pkg: RequestedPackage) => {
    if (paying) return;
    setPaying(pkg.id);
    try {
      const res = await stripeAPI.createTripPaymentIntent(pkg.id);
      const { clientSecret } = res.data;

      const { error: initError } = await initPaymentSheet({
        paymentIntentClientSecret: clientSecret,
        merchantDisplayName: 'Travel Odyssey',
        style: 'alwaysDark',
      });
      if (initError) {
        Alert.alert('Payment Error', initError.message);
        return;
      }

      const { error: presentError } = await presentPaymentSheet();
      if (presentError) {
        if (presentError.code !== 'Canceled') {
          Alert.alert('Payment Failed', presentError.message);
        }
        return;
      }

      // Optimistic update
      setRequestedPackages(
        requestedPackages.map((p) => p.id === pkg.id ? { ...p, status: 'confirmed' } : p)
      );
      Alert.alert('🎉 Payment Successful!', `Your ${pkg.destination} trip is confirmed. Our team will be in touch shortly.`);
    } catch (err: any) {
      Alert.alert('Error', err?.response?.data?.error || 'Payment could not be processed. Please try again.');
    } finally {
      setPaying(null);
    }
  };

  if (loading) {
    return <ActivityIndicator size="large" color={COLORS.secondary} style={{ marginTop: SPACING.xxxl }} />;
  }

  if (requestedPackages.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyEmoji}>🗺️</Text>
        <Text style={styles.emptyTitle}>No trip requests yet</Text>
        <Text style={styles.emptySubtitle}>
          Tap the ✨ button below to request a personalised trip — our experts will craft it for you!
        </Text>
        <TouchableOpacity style={styles.emptyBtn} onPress={() => (navigation as any).navigate('Generate')}>
          <Text style={styles.emptyBtnText}>Request a Trip</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <>
      {requestedPackages.map((pkg) => (
        <View key={pkg.id} style={styles.tripCard}>
          <Image
            source={{ uri: DEST_IMAGES[pkg.destination] || DEST_IMAGES.default }}
            style={styles.tripImage}
            resizeMode="cover"
          />
          <View style={styles.tripInfo}>
            <Text style={styles.tripDest}>{pkg.destination}</Text>
            {pkg.departure_location ? (
              <View style={styles.tripMeta}>
                <Ionicons name="airplane-outline" size={12} color={COLORS.textMuted} />
                <Text style={styles.tripDate}>from {pkg.departure_location}</Text>
              </View>
            ) : null}
            <View style={styles.tripMeta}>
              <Ionicons name="calendar-outline" size={12} color={COLORS.textMuted} />
              <Text style={styles.tripDate}>{pkg.start_date} → {pkg.end_date}</Text>
            </View>
            <View style={styles.tripMeta}>
              <Ionicons name="people-outline" size={12} color={COLORS.textMuted} />
              <Text style={styles.tripDate}>{pkg.guests} guest{pkg.guests !== 1 ? 's' : ''} · {pkg.duration} days</Text>
            </View>

            <View style={styles.tripFooter}>
              <StatusBadge status={pkg.status} />
              {pkg.status === 'ready' && pkg.price ? (
                <TouchableOpacity
                  style={[styles.payBtn, paying === pkg.id && styles.payBtnDisabled]}
                  onPress={() => handlePayNow(pkg)}
                  disabled={paying === pkg.id}
                >
                  {paying === pkg.id ? (
                    <ActivityIndicator size="small" color="#000" />
                  ) : (
                    <>
                      <Ionicons name="card-outline" size={14} color="#000" />
                      <Text style={styles.payBtnText}>Pay €{Number(pkg.price).toFixed(0)}</Text>
                    </>
                  )}
                </TouchableOpacity>
              ) : pkg.status === 'pending' ? (
                <View style={styles.craftingRow}>
                  <ActivityIndicator size="small" color={COLORS.accent} />
                  <Text style={styles.craftingText}>crafting...</Text>
                </View>
              ) : null}
            </View>
          </View>
        </View>
      ))}
    </>
  );
};

// ─── Upcoming Tab ─────────────────────────────────────────────────────────────

const UpcomingTab = ({ refreshing, onRefresh }: { refreshing: boolean; onRefresh: () => void }) => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { myBookings, setMyBookings } = useStore();
  const [loading, setLoading]   = useState(true);
  const [cancelling, setCancelling] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await bookingsAPI.getMyBookings();
      setMyBookings(Array.isArray(res.data) ? res.data : []);
    } catch {
      setMyBookings([]);
    } finally {
      setLoading(false);
    }
  }, [setMyBookings]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (refreshing) load();
  }, [refreshing, load]);

  const handleCancel = (bookingId: number) => {
    Alert.alert('Cancel Booking', 'Are you sure you want to cancel this booking?', [
      { text: 'Keep', style: 'cancel' },
      {
        text: 'Cancel Booking',
        style: 'destructive',
        onPress: async () => {
          setCancelling(bookingId);
          try {
            await bookingsAPI.cancel(bookingId);
            await load();
            Alert.alert('Booking Cancelled', 'Your booking has been cancelled.');
          } catch {
            Alert.alert('Error', 'Could not cancel booking. Please try again.');
          } finally {
            setCancelling(null);
          }
        },
      },
    ]);
  };

  const activeBookings = myBookings.filter((b) => !b.cancelled_at);

  if (loading) {
    return <ActivityIndicator size="large" color={COLORS.secondary} style={{ marginTop: SPACING.xxxl }} />;
  }

  if (activeBookings.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyEmoji}>🧳</Text>
        <Text style={styles.emptyTitle}>No upcoming trips yet</Text>
        <Text style={styles.emptySubtitle}>Book a package to see your upcoming trips here</Text>
        <TouchableOpacity style={styles.emptyBtn} onPress={() => (navigation as any).navigate('Generate')}>
          <Text style={styles.emptyBtnText}>Request a Trip</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <>
      {myBookings.map((booking) => (
        <View key={booking.id} style={styles.tripCard}>
          <Image
            source={{ uri: DEST_IMAGES[booking.destination] || DEST_IMAGES.default }}
            style={styles.tripImage}
            resizeMode="cover"
          />
          <View style={styles.tripInfo}>
            <View style={styles.tripHeader}>
              <Text style={styles.tripDest}>{booking.destination || `Booking #${booking.id}`}</Text>
            </View>
            {booking.start_date ? (
              <View style={styles.tripMeta}>
                <Ionicons name="calendar-outline" size={12} color={COLORS.textMuted} />
                <Text style={styles.tripDate}>{booking.start_date} → {booking.end_date}</Text>
              </View>
            ) : null}
            <View style={styles.tripFooter}>
              <StatusBadge status={booking.cancelled_at ? 'cancelled' : 'confirmed'} />
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
      ))}
    </>
  );
};

// ─── Saved Tab ────────────────────────────────────────────────────────────────

const SavedTab = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { savedPackages } = useStore();

  if (savedPackages.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyEmoji}>💫</Text>
        <Text style={styles.emptyTitle}>No saved packages yet</Text>
        <Text style={styles.emptySubtitle}>Save packages you love to compare later</Text>
        <TouchableOpacity style={styles.emptyBtn} onPress={() => (navigation as any).navigate('Home')}>
          <Text style={styles.emptyBtnText}>Explore Deals</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <>
      {savedPackages.map((pkg) => (
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
      ))}
    </>
  );
};

// ─── Main Screen ──────────────────────────────────────────────────────────────

type TabKey = 'requested' | 'upcoming' | 'saved';

export const TripsScreen: React.FC = () => {
  const { requestedPackages } = useStore();
  const [tab, setTab]         = useState<TabKey>('requested');
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = async () => {
    setRefreshing(true);
    // Child tabs react to refreshing prop; reset after a tick
    setTimeout(() => setRefreshing(false), 1500);
  };

  const readyCount = requestedPackages.filter((p) => p.status === 'ready').length;

  const tabConfig: { key: TabKey; label: string; badge?: number }[] = [
    { key: 'requested', label: 'Requested', badge: readyCount > 0 ? readyCount : undefined },
    { key: 'upcoming',  label: 'Upcoming' },
    { key: 'saved',     label: 'Saved' },
  ];

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <Text style={styles.title}>My Trips</Text>
      </View>

      {/* 3-tab switcher */}
      <View style={styles.tabs}>
        {tabConfig.map((t) => (
          <TouchableOpacity
            key={t.key}
            style={[styles.tab, tab === t.key && styles.tabActive]}
            onPress={() => setTab(t.key)}
          >
            <View style={styles.tabRow}>
              <Text style={[styles.tabText, tab === t.key && styles.tabTextActive]}>{t.label}</Text>
              {t.badge !== undefined && (
                <View style={styles.tabBadge}>
                  <Text style={styles.tabBadgeText}>{t.badge}</Text>
                </View>
              )}
            </View>
          </TouchableOpacity>
        ))}
      </View>

      <ScrollView
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.scroll}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={COLORS.secondary} />}
      >
        {tab === 'requested' && <RequestedTab refreshing={refreshing} onRefresh={onRefresh} />}
        {tab === 'upcoming'  && <UpcomingTab  refreshing={refreshing} onRefresh={onRefresh} />}
        {tab === 'saved'     && <SavedTab />}
        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container:      { flex: 1, backgroundColor: COLORS.background },
  header:         { paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md },
  title:          { color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },

  tabs: {
    flexDirection: 'row', marginHorizontal: SPACING.lg,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.lg,
    padding: 3, marginBottom: SPACING.lg,
  },
  tab:          { flex: 1, paddingVertical: SPACING.sm, alignItems: 'center', borderRadius: RADIUS.md },
  tabActive:    { backgroundColor: COLORS.secondary },
  tabRow:       { flexDirection: 'row', alignItems: 'center', gap: 4 },
  tabText:      { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  tabTextActive:{ color: COLORS.white },
  tabBadge: {
    backgroundColor: COLORS.accent, borderRadius: 10,
    minWidth: 16, height: 16, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 3,
  },
  tabBadgeText: { color: '#000', fontSize: 9, fontWeight: '800' },

  scroll: { paddingHorizontal: SPACING.lg },

  empty:          { alignItems: 'center', paddingTop: SPACING.xxxl },
  emptyEmoji:     { fontSize: 64, marginBottom: SPACING.lg },
  emptyTitle:     { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '700', marginBottom: SPACING.sm, textAlign: 'center' },
  emptySubtitle:  { color: COLORS.textMuted, fontSize: FONTS.sizes.md, textAlign: 'center', lineHeight: 22, marginBottom: SPACING.xl },
  emptyBtn:       { backgroundColor: COLORS.secondary, borderRadius: RADIUS.full, paddingHorizontal: SPACING.xl, paddingVertical: SPACING.md },
  emptyBtnText:   { color: COLORS.white, fontWeight: '700', fontSize: FONTS.sizes.md },

  tripCard: {
    flexDirection: 'row', backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl, overflow: 'hidden', marginBottom: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border,
  },
  tripImage:    { width: 90, height: 120 },
  tripInfo:     { flex: 1, padding: SPACING.md },
  tripHeader:   { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.xs },
  tripDest:     { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700', flex: 1, marginBottom: 4 },
  tripPrice:    { color: COLORS.accent, fontSize: FONTS.sizes.md, fontWeight: '700' },
  tripMeta:     { flexDirection: 'row', alignItems: 'center', gap: 4, marginBottom: 3 },
  tripDate:     { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
  tripFooter:   { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: SPACING.sm },

  statusBadge:  { borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical: 2 },
  statusText:   { fontSize: FONTS.sizes.xs, fontWeight: '600' },

  payBtn: {
    flexDirection: 'row', alignItems: 'center', gap: 5,
    backgroundColor: COLORS.accent, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md, paddingVertical: 6,
  },
  payBtnDisabled: { opacity: 0.6 },
  payBtnText:   { color: '#000', fontSize: FONTS.sizes.sm, fontWeight: '800' },

  craftingRow:  { flexDirection: 'row', alignItems: 'center', gap: 5 },
  craftingText: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },

  cancelBtn: {
    borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm, paddingVertical: 3,
    borderWidth: 1, borderColor: 'rgba(244,67,54,0.3)',
  },
  cancelBtnText:{ color: COLORS.error, fontSize: FONTS.sizes.xs, fontWeight: '600' },
});
