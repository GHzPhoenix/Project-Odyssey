import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Image,
  TextInput,
  StatusBar,
  Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList, TravelPackage } from '../../types';
import { PackageCard } from '../../components/PackageCard';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';

const { width } = Dimensions.get('window');

const CATEGORIES = [
  { id: 'all', label: 'All', icon: 'globe-outline' },
  { id: 'beach', label: 'Beach', icon: 'water-outline' },
  { id: 'city', label: 'City', icon: 'business-outline' },
  { id: 'adventure', label: 'Adventure', icon: 'bicycle-outline' },
  { id: 'culture', label: 'Culture', icon: 'library-outline' },
  { id: 'luxury', label: 'Luxury', icon: 'diamond-outline' },
];

const MOCK_PACKAGES: TravelPackage[] = [
  {
    id: '1', destination: 'London', country: 'UK', startDate: '2025-12-20', endDate: '2025-12-29',
    duration: 9, coverImage: '', price: 2890, originalPrice: 3400, rating: 4.9, reviewCount: 342,
    badge: 'Best Seller', isAIGenerated: true,
    summary: '', itinerary: [], included: [], highlights: [],
  },
  {
    id: '2', destination: 'Tokyo', country: 'Japan', startDate: '2025-03-15', endDate: '2025-03-25',
    duration: 10, coverImage: '', price: 3450, rating: 4.8, reviewCount: 218,
    badge: 'Cherry Blossom', isAIGenerated: true,
    summary: '', itinerary: [], included: [], highlights: [],
  },
  {
    id: '3', destination: 'Bali', country: 'Indonesia', startDate: '2025-07-01', endDate: '2025-07-10',
    duration: 9, coverImage: '', price: 1890, originalPrice: 2200, rating: 4.7, reviewCount: 156,
    badge: 'Popular', isAIGenerated: false,
    summary: '', itinerary: [], included: [], highlights: [],
  },
  {
    id: '4', destination: 'Santorini', country: 'Greece', startDate: '2025-06-01', endDate: '2025-06-08',
    duration: 7, coverImage: '', price: 2200, rating: 4.8, reviewCount: 203,
    badge: 'Romantic', isAIGenerated: false,
    summary: '', itinerary: [], included: [], highlights: [],
  },
  {
    id: '5', destination: 'Dubai', country: 'UAE', startDate: '2025-11-01', endDate: '2025-11-08',
    duration: 7, coverImage: '', price: 2600, rating: 4.6, reviewCount: 178,
    badge: 'Luxury', isAIGenerated: true,
    summary: '', itinerary: [], included: [], highlights: [],
  },
];

export const ExploreScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');

  const filtered = MOCK_PACKAGES.filter((p) =>
    p.destination.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Explore</Text>
        <Text style={styles.subtitle}>Discover your next adventure</Text>

        {/* Search */}
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
        {/* Categories */}
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
              <Text
                style={[styles.categoryText, activeCategory === cat.id && styles.categoryTextActive]}
              >
                {cat.label}
              </Text>
            </TouchableOpacity>
          ))}
        </ScrollView>

        {/* Results */}
        <View style={styles.results}>
          <Text style={styles.resultCount}>{filtered.length} packages found</Text>
          {filtered.map((pkg) => (
            <PackageCard
              key={pkg.id}
              package={pkg}
              onPress={() => navigation.navigate('PackageDetail', { packageId: pkg.id })}
            />
          ))}
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
});
