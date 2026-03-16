import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Image,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';

const DESTINATION_IMAGES: Record<string, string> = {
  London: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=400',
  Tokyo: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=400',
  Paris: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=400',
  default: 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=400',
};

export const TripsScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { myTrips, savedPackages } = useStore();
  const [tab, setTab] = useState<'upcoming' | 'saved'>('upcoming');

  const items = tab === 'upcoming' ? myTrips : savedPackages;

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <Text style={styles.title}>My Trips</Text>
      </View>

      {/* Tabs */}
      <View style={styles.tabs}>
        <TouchableOpacity
          style={[styles.tab, tab === 'upcoming' && styles.tabActive]}
          onPress={() => setTab('upcoming')}
        >
          <Text style={[styles.tabText, tab === 'upcoming' && styles.tabTextActive]}>Upcoming</Text>
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

      <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.scroll}>
        {items.length === 0 ? (
          <View style={styles.empty}>
            <Text style={styles.emptyEmoji}>{tab === 'upcoming' ? '🧳' : '💫'}</Text>
            <Text style={styles.emptyTitle}>
              {tab === 'upcoming' ? 'No upcoming trips yet' : 'No saved packages yet'}
            </Text>
            <Text style={styles.emptySubtitle}>
              {tab === 'upcoming'
                ? 'Book a package to see your upcoming trips here'
                : 'Save packages you love to compare later'}
            </Text>
            <TouchableOpacity
              style={styles.emptyBtn}
              onPress={() => navigation.navigate('GeneratePackage')}
            >
              <Text style={styles.emptyBtnText}>
                {tab === 'upcoming' ? 'Generate a Package' : 'Explore Packages'}
              </Text>
            </TouchableOpacity>
          </View>
        ) : (
          items.map((pkg) => (
            <TouchableOpacity
              key={pkg.id}
              style={styles.tripCard}
              onPress={() => navigation.navigate('PackageDetail', { packageId: pkg.id })}
              activeOpacity={0.85}
            >
              <Image
                source={{ uri: DESTINATION_IMAGES[pkg.destination] || DESTINATION_IMAGES.default }}
                style={styles.tripImage}
                resizeMode="cover"
              />
              <View style={styles.tripInfo}>
                <View style={styles.tripHeader}>
                  <Text style={styles.tripDest}>{pkg.destination}</Text>
                  <Text style={styles.tripPrice}>€{pkg.price.toLocaleString()}</Text>
                </View>
                <View style={styles.tripMeta}>
                  <Ionicons name="calendar-outline" size={12} color={COLORS.textMuted} />
                  <Text style={styles.tripDate}>
                    {pkg.startDate} → {pkg.endDate}
                  </Text>
                </View>
                <View style={styles.tripMeta}>
                  <Ionicons name="time-outline" size={12} color={COLORS.textMuted} />
                  <Text style={styles.tripDate}>{pkg.duration} days</Text>
                </View>
              </View>
            </TouchableOpacity>
          ))
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
  tripImage: { width: 90, height: 90 },
  tripInfo: { flex: 1, padding: SPACING.md },
  tripHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: SPACING.xs },
  tripDest: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  tripPrice: { color: COLORS.accent, fontSize: FONTS.sizes.md, fontWeight: '700' },
  tripMeta: { flexDirection: 'row', alignItems: 'center', gap: 4, marginBottom: 3 },
  tripDate: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs },
});
