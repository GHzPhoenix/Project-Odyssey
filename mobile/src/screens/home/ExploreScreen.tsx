import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  TextInput,
  StatusBar,
  ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { PackageCard } from '../../components/PackageCard';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { packagesAPI } from '../../services/api';

const CATEGORIES = [
  { id: 'all', label: 'All', icon: 'globe-outline' },
  { id: 'beach', label: 'Beach', icon: 'water-outline' },
  { id: 'city', label: 'City', icon: 'business-outline' },
  { id: 'adventure', label: 'Adventure', icon: 'bicycle-outline' },
  { id: 'culture', label: 'Culture', icon: 'library-outline' },
  { id: 'luxury', label: 'Luxury', icon: 'diamond-outline' },
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

export const ExploreScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');
  const [allPackages, setAllPackages] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadDeals = useCallback(async () => {
    try {
      const res = await packagesAPI.getFeatured();
      const deals = Array.isArray(res.data) ? res.data : [];
      setAllPackages(deals.map(dealToPackage));
    } catch {
      setAllPackages([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDeals(); }, [loadDeals]);

  const filtered = allPackages.filter((p) => {
    const matchesSearch = p.destination.toLowerCase().includes(search.toLowerCase());
    if (activeCategory === 'all') return matchesSearch;
    if (activeCategory === 'beach') return matchesSearch && /bali|santorini|maldiv|hawaii/i.test(p.destination);
    if (activeCategory === 'city') return matchesSearch && /london|paris|tokyo|dubai|rome|barcelona|york/i.test(p.destination);
    if (activeCategory === 'luxury') return matchesSearch && /dubai|maldiv|monaco/i.test(p.destination);
    return matchesSearch;
  });

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      <View style={styles.header}>
        <Text style={styles.title}>Explore</Text>
        <Text style={styles.subtitle}>Discover your next adventure</Text>
        <View style={styles.searchBar}>
          <Ionicons name="search-outline" size={18} color={COLORS.textMuted} />
          <TextInput
            style={styles.searchInput}
            placeholder="Search destinations..."
            placeholderTextColor={COLORS.textMuted}
            value={search}
            onChangeText={setSearch}
          />
          {search ? (
            <TouchableOpacity onPress={() => setSearch('')}>
              <Ionicons name="close-circle" size={16} color={COLORS.textMuted} />
            </TouchableOpacity>
          ) : null}
        </View>
      </View>

      <ScrollView showsVerticalScrollIndicator={false}>
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.categories}
        >
          {CATEGORIES.map((cat) => (
            <TouchableOpacity
              key={cat.id}
              style={[styles.category, activeCategory === cat.id && styles.categoryActive]}
              onPress={() => setActiveCategory(cat.id)}
            >
              <Ionicons
                name={cat.icon as any}
                size={16}
                color={activeCategory === cat.id ? COLORS.white : COLORS.textSecondary}
              />
              <Text style={[styles.categoryText, activeCategory === cat.id && styles.categoryTextActive]}>
                {cat.label}
              </Text>
            </TouchableOpacity>
          ))}
        </ScrollView>

        <View style={styles.results}>
          {loading ? (
            <ActivityIndicator size="large" color={COLORS.secondary} style={{ marginTop: SPACING.xl }} />
          ) : (
            <>
              <Text style={styles.resultCount}>{filtered.length} packages found</Text>
              {filtered.length === 0 ? (
                <View style={styles.empty}>
                  <Text style={styles.emptyEmoji}>🌍</Text>
                  <Text style={styles.emptyText}>No packages found</Text>
                  <Text style={styles.emptySubtext}>Try a different search or category</Text>
                </View>
              ) : (
                filtered.map((pkg) => (
                  <PackageCard
                    key={pkg.id}
                    package={pkg}
                    onPress={() => navigation.navigate('PackageDetail', { packageId: pkg.id })}
                  />
                ))
              )}
            </>
          )}
        </View>

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: { paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md },
  title: { color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  subtitle: { color: COLORS.textSecondary, fontSize: FONTS.sizes.md, marginBottom: SPACING.md },
  searchBar: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.sm,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm + 2,
    borderWidth: 1, borderColor: COLORS.border,
  },
  searchInput: { flex: 1, color: COLORS.text, fontSize: FONTS.sizes.md },
  categories: { paddingHorizontal: SPACING.lg, gap: SPACING.sm, marginBottom: SPACING.md },
  category: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.xs,
    paddingHorizontal: SPACING.md, paddingVertical: SPACING.sm,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.full,
    borderWidth: 1.5, borderColor: COLORS.border,
  },
  categoryActive: { backgroundColor: COLORS.secondary, borderColor: COLORS.secondary },
  categoryText: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  categoryTextActive: { color: COLORS.white },
  results: { paddingHorizontal: SPACING.lg },
  resultCount: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, marginBottom: SPACING.md },
  empty: { alignItems: 'center', paddingTop: SPACING.xxxl },
  emptyEmoji: { fontSize: 48, marginBottom: SPACING.md },
  emptyText: { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '700', marginBottom: SPACING.sm },
  emptySubtext: { color: COLORS.textMuted, fontSize: FONTS.sizes.md },
});
