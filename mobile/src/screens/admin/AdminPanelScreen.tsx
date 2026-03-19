import React, { useState, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Alert,
  TextInput,
  RefreshControl,
  ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { adminAPI } from '../../services/api';
import { useFocusEffect } from '@react-navigation/native';

interface AdminPackage {
  id: number;
  destination: string;
  departure_location: string | null;
  start_date: string;
  end_date: string;
  duration: number;
  guests: number;
  price: number | null;
  status: 'pending' | 'ready' | 'confirmed';
  created_at: string;
  user_name: string;
  user_email: string;
}

const formatDate = (iso: string) => {
  const d = new Date(iso);
  return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()}`;
};

const STATUS_COLOR: Record<string, string> = {
  pending:   '#F5A623',
  ready:     '#C9A84C',
  confirmed: '#4CAF50',
};

export const AdminPanelScreen: React.FC = () => {
  const navigation = useNavigation<any>();
  const [packages, setPackages]   = useState<AdminPackage[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [priceInputs, setPriceInputs] = useState<Record<number, string>>({});
  const [marking, setMarking]     = useState<number | null>(null);

  const loadPackages = useCallback(async () => {
    try {
      const res = await adminAPI.getAllPackages();
      setPackages(res.data);
    } catch {
      Alert.alert('Error', 'Could not load trip requests.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useFocusEffect(useCallback(() => { loadPackages(); }, [loadPackages]));

  const handleMarkReady = async (pkg: AdminPackage) => {
    const priceStr = priceInputs[pkg.id]?.trim();
    const price = parseFloat(priceStr || '');
    if (!priceStr || isNaN(price) || price <= 0) {
      Alert.alert('Enter Price', 'Please enter a valid price (€) before marking as ready.');
      return;
    }

    Alert.alert(
      'Mark as Ready',
      `Send "${pkg.destination}" package to ${pkg.user_name} for €${price.toFixed(0)}?\n\nThey will receive a push notification and email.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Send',
          onPress: async () => {
            setMarking(pkg.id);
            try {
              await adminAPI.markReady(pkg.id, price);
              Alert.alert('✅ Done!', `${pkg.user_name} has been notified. Their trip is now ready to pay.`);
              loadPackages();
            } catch (err: any) {
              Alert.alert('Error', err?.response?.data?.error || 'Failed to mark as ready.');
            } finally {
              setMarking(null);
            }
          },
        },
      ]
    );
  };

  const pending   = packages.filter(p => p.status === 'pending');
  const ready     = packages.filter(p => p.status === 'ready');
  const confirmed = packages.filter(p => p.status === 'confirmed');

  const renderCard = (pkg: AdminPackage) => (
    <View key={pkg.id} style={styles.card}>
      {/* Card Header */}
      <View style={styles.cardHeader}>
        <View style={styles.cardTitleRow}>
          <Text style={styles.cardDestination}>{pkg.destination}</Text>
          <View style={[styles.statusBadge, { backgroundColor: STATUS_COLOR[pkg.status] + '25', borderColor: STATUS_COLOR[pkg.status] + '60' }]}>
            <Text style={[styles.statusText, { color: STATUS_COLOR[pkg.status] }]}>
              {pkg.status.charAt(0).toUpperCase() + pkg.status.slice(1)}
            </Text>
          </View>
        </View>
        <Text style={styles.cardUser}>
          <Ionicons name="person-outline" size={12} color={COLORS.textMuted} /> {pkg.user_name} · {pkg.user_email}
        </Text>
      </View>

      {/* Details */}
      <View style={styles.cardBody}>
        <View style={styles.detailRow}>
          <Ionicons name="airplane-outline" size={14} color={COLORS.textMuted} />
          <Text style={styles.detailText}>
            {pkg.departure_location ? `From ${pkg.departure_location}` : 'Departure not specified'}
          </Text>
        </View>
        <View style={styles.detailRow}>
          <Ionicons name="calendar-outline" size={14} color={COLORS.textMuted} />
          <Text style={styles.detailText}>
            {formatDate(pkg.start_date)} → {formatDate(pkg.end_date)} ({pkg.duration} days)
          </Text>
        </View>
        <View style={styles.detailRow}>
          <Ionicons name="people-outline" size={14} color={COLORS.textMuted} />
          <Text style={styles.detailText}>{pkg.guests} {pkg.guests === 1 ? 'guest' : 'guests'}</Text>
        </View>
        <View style={styles.detailRow}>
          <Ionicons name="time-outline" size={14} color={COLORS.textMuted} />
          <Text style={styles.detailText}>Requested {formatDate(pkg.created_at)}</Text>
        </View>
        {pkg.price && (
          <View style={styles.detailRow}>
            <Ionicons name="pricetag-outline" size={14} color={COLORS.accent} />
            <Text style={[styles.detailText, { color: COLORS.accent, fontWeight: '700' }]}>
              €{pkg.price}
            </Text>
          </View>
        )}
      </View>

      {/* Action — only for pending */}
      {pkg.status === 'pending' && (
        <View style={styles.cardAction}>
          <View style={styles.priceInputRow}>
            <Text style={styles.euroSign}>€</Text>
            <TextInput
              style={styles.priceInput}
              placeholder="Set price"
              placeholderTextColor={COLORS.textMuted}
              keyboardType="number-pad"
              value={priceInputs[pkg.id] || ''}
              onChangeText={(t) => setPriceInputs(prev => ({ ...prev, [pkg.id]: t }))}
            />
          </View>
          <TouchableOpacity
            style={[styles.readyBtn, marking === pkg.id && { opacity: 0.6 }]}
            onPress={() => handleMarkReady(pkg)}
            disabled={marking === pkg.id}
          >
            {marking === pkg.id
              ? <ActivityIndicator size="small" color={COLORS.primary} />
              : <>
                  <Ionicons name="checkmark-circle" size={16} color={COLORS.primary} />
                  <Text style={styles.readyBtnText}>Mark Ready</Text>
                </>
            }
          </TouchableOpacity>
        </View>
      )}
    </View>
  );

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <TouchableOpacity style={styles.backBtn} onPress={() => navigation.goBack()}>
          <Ionicons name="arrow-back" size={20} color={COLORS.text} />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Trip Requests</Text>
        <TouchableOpacity style={styles.createBtn} onPress={() => navigation.navigate('CreatePackage')}>
          <Ionicons name="add" size={20} color={COLORS.white} />
        </TouchableOpacity>
      </View>

      {/* Stats row */}
      <View style={styles.statsRow}>
        {[
          { label: 'Pending',   count: pending.length,   color: '#F5A623' },
          { label: 'Ready',     count: ready.length,     color: '#C9A84C' },
          { label: 'Confirmed', count: confirmed.length, color: '#4CAF50' },
        ].map((s) => (
          <View key={s.label} style={styles.stat}>
            <Text style={[styles.statCount, { color: s.color }]}>{s.count}</Text>
            <Text style={styles.statLabel}>{s.label}</Text>
          </View>
        ))}
      </View>

      {loading ? (
        <ActivityIndicator color={COLORS.secondary} size="large" style={{ marginTop: 60 }} />
      ) : (
        <ScrollView
          showsVerticalScrollIndicator={false}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); loadPackages(); }} tintColor={COLORS.secondary} />}
          contentContainerStyle={styles.list}
        >
          {packages.length === 0 ? (
            <View style={styles.empty}>
              <Ionicons name="airplane-outline" size={48} color={COLORS.textMuted} />
              <Text style={styles.emptyText}>No trip requests yet</Text>
            </View>
          ) : (
            <>
              {pending.length > 0 && (
                <>
                  <Text style={styles.sectionTitle}>⏳ Pending — needs action</Text>
                  {pending.map(renderCard)}
                </>
              )}
              {ready.length > 0 && (
                <>
                  <Text style={styles.sectionTitle}>✅ Ready — awaiting payment</Text>
                  {ready.map(renderCard)}
                </>
              )}
              {confirmed.length > 0 && (
                <>
                  <Text style={styles.sectionTitle}>💚 Confirmed</Text>
                  {confirmed.map(renderCard)}
                </>
              )}
            </>
          )}
          <View style={{ height: SPACING.xxxl }} />
        </ScrollView>
      )}
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
  createBtn: {
    width: 38, height: 38, borderRadius: RADIUS.full,
    backgroundColor: COLORS.secondary, alignItems: 'center', justifyContent: 'center',
  },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },

  statsRow: {
    flexDirection: 'row', marginHorizontal: SPACING.lg, marginBottom: SPACING.md,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    borderWidth: 1, borderColor: COLORS.border,
  },
  stat: { flex: 1, alignItems: 'center', padding: SPACING.md },
  statCount: { fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  statLabel: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },

  list: { paddingHorizontal: SPACING.lg },

  sectionTitle: {
    color: COLORS.textSecondary, fontSize: FONTS.sizes.sm,
    fontWeight: '700', letterSpacing: 0.3,
    marginBottom: SPACING.sm, marginTop: SPACING.md,
  },

  card: {
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    borderWidth: 1, borderColor: COLORS.border,
    marginBottom: SPACING.md, overflow: 'hidden',
  },
  cardHeader: {
    padding: SPACING.md, borderBottomWidth: 1, borderBottomColor: COLORS.border,
  },
  cardTitleRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 },
  cardDestination: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700', flex: 1 },
  statusBadge: {
    borderRadius: RADIUS.full, paddingHorizontal: SPACING.sm,
    paddingVertical: 3, borderWidth: 1,
  },
  statusText: { fontSize: FONTS.sizes.xs, fontWeight: '700' },
  cardUser: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },

  cardBody: { padding: SPACING.md, gap: SPACING.xs },
  detailRow: { flexDirection: 'row', alignItems: 'center', gap: SPACING.sm },
  detailText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, flex: 1 },

  cardAction: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.sm,
    padding: SPACING.md, borderTopWidth: 1, borderTopColor: COLORS.border,
    backgroundColor: 'rgba(201,168,76,0.05)',
  },
  priceInputRow: {
    flex: 1, flexDirection: 'row', alignItems: 'center',
    backgroundColor: COLORS.background, borderRadius: RADIUS.md,
    borderWidth: 1, borderColor: COLORS.border,
    paddingHorizontal: SPACING.sm,
  },
  euroSign: { color: COLORS.accent, fontSize: FONTS.sizes.lg, fontWeight: '700', paddingRight: 4 },
  priceInput: { flex: 1, color: COLORS.text, fontSize: FONTS.sizes.md, paddingVertical: SPACING.sm },
  readyBtn: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.xs,
    backgroundColor: COLORS.accent, borderRadius: RADIUS.md,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm + 2,
  },
  readyBtnText: { color: COLORS.primary, fontWeight: '700', fontSize: FONTS.sizes.sm },

  empty: { alignItems: 'center', marginTop: 80, gap: SPACING.md },
  emptyText: { color: COLORS.textMuted, fontSize: FONTS.sizes.md },
});
