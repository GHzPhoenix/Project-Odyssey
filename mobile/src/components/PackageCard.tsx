import React from 'react';
import {
  View,
  Text,
  Image,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { TravelPackage } from '../types';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../constants/theme';
import { useStore } from '../store/useStore';

const { width } = Dimensions.get('window');

interface Props {
  package: TravelPackage;
  onPress: () => void;
  size?: 'large' | 'medium' | 'small';
}

const DESTINATION_IMAGES: Record<string, string> = {
  London: 'https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?w=800',
  Paris: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?w=800',
  Tokyo: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=800',
  Dubai: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c?w=800',
  Rome: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5?w=800',
  Barcelona: 'https://images.unsplash.com/photo-1539037116277-4db20889f2d4?w=800',
  Bali: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4?w=800',
  Sydney: 'https://images.unsplash.com/photo-1506973035872-a4ec16b8e8d9?w=800',
  default: 'https://images.unsplash.com/photo-1488085061387-422e29b40080?w=800',
};

export const PackageCard: React.FC<Props> = ({ package: pkg, onPress, size = 'large' }) => {
  const { savedPackages, savePackage, unsavePackage } = useStore();
  const isSaved = savedPackages.some((p) => p.id === pkg.id);
  const imageUrl = pkg.coverImage || DESTINATION_IMAGES[pkg.destination] || DESTINATION_IMAGES.default;

  const cardWidth = size === 'large' ? width - SPACING.lg * 2 : size === 'medium' ? width * 0.65 : width * 0.45;
  const cardHeight = size === 'large' ? 240 : size === 'medium' ? 200 : 160;

  return (
    <TouchableOpacity
      style={[styles.card, { width: cardWidth }, SHADOWS.md]}
      onPress={onPress}
      activeOpacity={0.9}
    >
      <Image
        source={{ uri: imageUrl }}
        style={[styles.image, { height: cardHeight }]}
        resizeMode="cover"
      />

      {/* Overlay */}
      <View style={styles.overlay} />

      {/* Badges */}
      <View style={styles.topRow}>
        {pkg.badge && (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{pkg.badge}</Text>
          </View>
        )}
        {pkg.isAIGenerated && (
          <View style={styles.aiBadge}>
            <Ionicons name="sparkles" size={10} color={COLORS.accent} />
            <Text style={styles.aiBadgeText}>AI Curated</Text>
          </View>
        )}
        <TouchableOpacity
          style={styles.saveBtn}
          onPress={() => isSaved ? unsavePackage(pkg.id) : savePackage(pkg)}
        >
          <Ionicons
            name={isSaved ? 'heart' : 'heart-outline'}
            size={18}
            color={isSaved ? '#FF4B6E' : COLORS.white}
          />
        </TouchableOpacity>
      </View>

      {/* Bottom Info */}
      <View style={styles.info}>
        <View style={styles.infoTop}>
          <Text style={styles.destination}>{pkg.destination}</Text>
          <View style={styles.rating}>
            <Ionicons name="star" size={12} color={COLORS.accent} />
            <Text style={styles.ratingText}>{Number(pkg.rating ?? 4.5).toFixed(1)}</Text>
          </View>
        </View>
        <View style={styles.infoBottom}>
          <View style={styles.durationRow}>
            <Ionicons name="calendar-outline" size={12} color={COLORS.textSecondary} />
            <Text style={styles.duration}>{pkg.duration} days</Text>
          </View>
          <View style={styles.priceRow}>
            {pkg.originalPrice && (
              <Text style={styles.originalPrice}>€{pkg.originalPrice.toLocaleString()}</Text>
            )}
            <Text style={styles.price}>€{pkg.price.toLocaleString()}</Text>
          </View>
        </View>
      </View>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  card: {
    borderRadius: RADIUS.xl,
    overflow: 'hidden',
    backgroundColor: COLORS.card,
    marginBottom: SPACING.md,
  },
  image: {
    width: '100%',
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0,0,0,0.25)',
    borderRadius: RADIUS.xl,
  },
  topRow: {
    position: 'absolute',
    top: SPACING.md,
    left: SPACING.md,
    right: SPACING.md,
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.sm,
  },
  badge: {
    backgroundColor: COLORS.accent,
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm,
    paddingVertical: 3,
  },
  badgeText: {
    color: COLORS.primary,
    fontSize: FONTS.sizes.xs,
    fontWeight: '700',
  },
  aiBadge: {
    backgroundColor: 'rgba(108,60,225,0.8)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm,
    paddingVertical: 3,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 3,
  },
  aiBadgeText: {
    color: COLORS.white,
    fontSize: FONTS.sizes.xs,
    fontWeight: '600',
  },
  saveBtn: {
    marginLeft: 'auto',
    backgroundColor: 'rgba(0,0,0,0.35)',
    borderRadius: RADIUS.full,
    padding: SPACING.xs,
  },
  info: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    padding: SPACING.md,
    paddingTop: SPACING.xl,
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  infoTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: SPACING.xs,
  },
  destination: {
    color: COLORS.white,
    fontSize: FONTS.sizes.xl,
    fontWeight: '700',
  },
  rating: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 3,
    backgroundColor: 'rgba(0,0,0,0.4)',
    borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm,
    paddingVertical: 2,
  },
  ratingText: {
    color: COLORS.white,
    fontSize: FONTS.sizes.xs,
    fontWeight: '600',
  },
  infoBottom: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  durationRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  duration: {
    color: COLORS.textSecondary,
    fontSize: FONTS.sizes.sm,
  },
  priceRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: SPACING.xs,
  },
  originalPrice: {
    color: COLORS.textMuted,
    fontSize: FONTS.sizes.sm,
    textDecorationLine: 'line-through',
  },
  price: {
    color: COLORS.accent,
    fontSize: FONTS.sizes.lg,
    fontWeight: '700',
  },
});
