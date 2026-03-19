import React, { useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  StatusBar,
  Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../types';
import { COLORS, FONTS, SPACING, RADIUS } from '../../constants/theme';
import { useStore } from '../../store/useStore';
import { preferencesAPI, subscriptionAPI } from '../../services/api';

export const ProfileScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { user, logout, updatePreferences, setMembership, savedPackages, myBookings } = useStore();

  const loadProfile = useCallback(async () => {
    try {
      const [prefsRes, membershipRes] = await Promise.allSettled([
        preferencesAPI.get(),
        subscriptionAPI.getMembership(),
      ]);

      if (prefsRes.status === 'fulfilled' && prefsRes.value.data) {
        const p = prefsRes.value.data;
        updatePreferences({
          cuisines: p.cuisines ? JSON.parse(p.cuisines) : [],
          activities: p.activities ? JSON.parse(p.activities) : [],
          travelStyle: p.travel_style || '',
          budgetTier: p.budget_tier || '',
          dietaryRestrictions: p.dietary_restrictions ? JSON.parse(p.dietary_restrictions) : [],
          accommodation: p.accommodation || '',
          companions: p.companions || '',
          pacePreference: p.pace_preference || '',
        });
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
  }, [updatePreferences, setMembership]);

  useEffect(() => { loadProfile(); }, [loadProfile]);

  const handleLogout = () => {
    Alert.alert('Sign Out', 'Are you sure you want to sign out?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Sign Out',
        style: 'destructive',
        onPress: async () => {
          await logout();
          navigation.replace('Welcome');
        },
      },
    ]);
  };

  const handleMenuPress = (label: string) => {
    switch (label) {
      case 'Saved Packages':
        (navigation as any).navigate('Main', { screen: 'Trips' });
        break;
      case 'My Preferences':
        navigation.navigate('Onboarding');
        break;
      case 'Membership & Plans':
        navigation.navigate('Plans');
        break;
      case 'Notifications':
        navigation.navigate('NotificationSettings');
        break;
      case 'Privacy & Security':
        navigation.navigate('PrivacySecurity');
        break;
      case 'Help & Support':
        Alert.alert('Help & Support', 'For support, contact us at support@travelodyssey.com');
        break;
      case 'About':
        Alert.alert('Travel Odyssey', 'Version 1.0.0\n\nHandcrafted, personalised travel experiences.');
        break;
      case 'Admin Panel':
        navigation.navigate('AdminPanel');
        break;
      default:
        Alert.alert(label, 'This feature is coming soon.');
    }
  };

  const getInitials = (name?: string) => {
    if (!name) return 'T';
    return name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);
  };

  const activeBookings = myBookings.filter((b) => !b.cancelled_at).length;

  const accountItems = [
    { icon: 'heart-outline', label: 'Saved Packages', section: 'account' },
    { icon: 'sparkles-outline', label: 'My Preferences', section: 'account' },
    { icon: 'diamond-outline', label: 'Membership & Plans', section: 'account', accent: true },
  ];

  const settingsItems = [
    { icon: 'notifications-outline', label: 'Notifications', section: 'settings' },
    { icon: 'shield-outline', label: 'Privacy & Security', section: 'settings' },
    { icon: 'help-circle-outline', label: 'Help & Support', section: 'settings' },
    { icon: 'information-circle-outline', label: 'About', section: 'settings' },
  ];

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />
      <ScrollView showsVerticalScrollIndicator={false}>
        <View style={styles.header}>
          <Text style={styles.headerTitle}>Profile</Text>
        </View>

        {/* User Card */}
        <View style={styles.userCard}>
          <View style={styles.avatar}>
            <Text style={styles.avatarText}>{getInitials(user?.name)}</Text>
          </View>
          <View style={styles.userInfo}>
            <Text style={styles.userName}>{user?.name || 'Traveler'}</Text>
            <Text style={styles.userEmail}>{user?.email || ''}</Text>
            {user?.membership ? (
              <View style={styles.memberBadge}>
                <Ionicons name="diamond" size={10} color={COLORS.accent} />
                <Text style={styles.memberBadgeText}>
                  {user.membership.type.charAt(0).toUpperCase() + user.membership.type.slice(1)} Member
                </Text>
              </View>
            ) : (
              <TouchableOpacity style={styles.upgradeBadge} onPress={() => navigation.navigate('Plans')}>
                <Text style={styles.upgradeBadgeText}>Upgrade to unlock all features</Text>
                <Ionicons name="arrow-forward" size={10} color={COLORS.secondary} />
              </TouchableOpacity>
            )}
          </View>
        </View>

        {/* Stats Row */}
        <View style={styles.statsRow}>
          {[
            { value: String(activeBookings), label: 'Trips' },
            { value: String(savedPackages.length), label: 'Saved' },
          ].map((stat, i) => (
            <View key={i} style={styles.stat}>
              <Text style={styles.statValue}>{stat.value}</Text>
              <Text style={styles.statLabel}>{stat.label}</Text>
            </View>
          ))}
          <View style={styles.stat}>
            <Text style={styles.statValue}>{user?.membership ? '✦' : '—'}</Text>
            <Text style={styles.statLabel}>Plan</Text>
          </View>
        </View>

        {/* Preferences Preview */}
        {user?.preferences && (
          <View style={styles.prefsCard}>
            <View style={styles.prefsHeader}>
              <Ionicons name="sparkles" size={16} color={COLORS.accent} />
              <Text style={styles.prefsTitle}>Your Travel DNA</Text>
              <TouchableOpacity onPress={() => navigation.navigate('Onboarding')}>
                <Text style={styles.prefsEdit}>Edit</Text>
              </TouchableOpacity>
            </View>
            <View style={styles.prefChips}>
              {[
                user.preferences.travelStyle,
                user.preferences.budgetTier,
                user.preferences.companions,
                ...(user.preferences.activities || []).slice(0, 2),
              ].filter(Boolean).map((pref, i) => (
                <View key={i} style={styles.prefChip}>
                  <Text style={styles.prefChipText}>{pref}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* Account Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Account</Text>
          <View style={styles.menuCard}>
            {accountItems.map((item, i) => (
              <TouchableOpacity
                key={i}
                style={[styles.menuItem, i < accountItems.length - 1 && styles.menuItemBorder]}
                onPress={() => handleMenuPress(item.label)}
              >
                <View style={[styles.menuIcon, item.accent && styles.menuIconAccent]}>
                  <Ionicons name={item.icon as any} size={18} color={item.accent ? COLORS.accent : COLORS.textSecondary} />
                </View>
                <Text style={[styles.menuLabel, item.accent && styles.menuLabelAccent]}>{item.label}</Text>
                <Ionicons name="chevron-forward" size={16} color={COLORS.textMuted} />
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Settings Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Settings</Text>
          <View style={styles.menuCard}>
            {settingsItems.map((item, i) => (
              <TouchableOpacity
                key={i}
                style={[styles.menuItem, i < settingsItems.length - 1 && styles.menuItemBorder]}
                onPress={() => handleMenuPress(item.label)}
              >
                <View style={styles.menuIcon}>
                  <Ionicons name={item.icon as any} size={18} color={COLORS.textSecondary} />
                </View>
                <Text style={styles.menuLabel}>{item.label}</Text>
                <Ionicons name="chevron-forward" size={16} color={COLORS.textMuted} />
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Admin Panel — only visible to admin users */}
        {user?.role === 'admin' && (
          <TouchableOpacity
            style={styles.adminBtn}
            onPress={() => navigation.navigate('AdminPanel')}
            activeOpacity={0.85}
          >
            <Ionicons name="shield-checkmark" size={18} color={COLORS.white} />
            <Text style={styles.adminBtnText}>Admin Panel — Trip Requests</Text>
            <Ionicons name="chevron-forward" size={16} color={COLORS.white} />
          </TouchableOpacity>
        )}

        <TouchableOpacity style={styles.signOutBtn} onPress={handleLogout}>
          <Ionicons name="log-out-outline" size={18} color={COLORS.error} />
          <Text style={styles.signOutText}>Sign Out</Text>
        </TouchableOpacity>

        <View style={{ height: SPACING.xxxl }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.background },
  header: { paddingHorizontal: SPACING.lg, paddingTop: SPACING.xxl, paddingBottom: SPACING.md },
  headerTitle: { color: COLORS.text, fontSize: FONTS.sizes.xxl, fontWeight: '800' },
  userCard: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.md,
    marginHorizontal: SPACING.lg, backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl, padding: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border, marginBottom: SPACING.md,
  },
  avatar: {
    width: 60, height: 60, borderRadius: RADIUS.full,
    backgroundColor: COLORS.secondary, alignItems: 'center', justifyContent: 'center',
  },
  avatarText: { color: COLORS.white, fontSize: FONTS.sizes.xl, fontWeight: '800' },
  userInfo: { flex: 1 },
  userName: { color: COLORS.text, fontSize: FONTS.sizes.lg, fontWeight: '700' },
  userEmail: { color: COLORS.textMuted, fontSize: FONTS.sizes.sm, marginTop: 2 },
  memberBadge: {
    flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: 'rgba(245,166,35,0.15)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 2, alignSelf: 'flex-start', marginTop: SPACING.xs,
  },
  memberBadgeText: { color: COLORS.accent, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  upgradeBadge: { flexDirection: 'row', alignItems: 'center', gap: 4, marginTop: SPACING.xs },
  upgradeBadgeText: { color: COLORS.secondary, fontSize: FONTS.sizes.xs, fontWeight: '600' },
  statsRow: {
    flexDirection: 'row', marginHorizontal: SPACING.lg,
    backgroundColor: COLORS.surface, borderRadius: RADIUS.xl,
    marginBottom: SPACING.md, borderWidth: 1, borderColor: COLORS.border,
  },
  stat: { flex: 1, alignItems: 'center', padding: SPACING.md },
  statValue: { color: COLORS.text, fontSize: FONTS.sizes.xl, fontWeight: '800' },
  statLabel: { color: COLORS.textMuted, fontSize: FONTS.sizes.xs, marginTop: 2 },
  prefsCard: {
    marginHorizontal: SPACING.lg, backgroundColor: COLORS.surface,
    borderRadius: RADIUS.xl, padding: SPACING.md,
    borderWidth: 1, borderColor: COLORS.border, marginBottom: SPACING.md,
  },
  prefsHeader: { flexDirection: 'row', alignItems: 'center', gap: SPACING.sm, marginBottom: SPACING.md },
  prefsTitle: { color: COLORS.text, fontSize: FONTS.sizes.md, fontWeight: '700', flex: 1 },
  prefsEdit: { color: COLORS.secondary, fontSize: FONTS.sizes.sm, fontWeight: '600' },
  prefChips: { flexDirection: 'row', flexWrap: 'wrap', gap: SPACING.xs },
  prefChip: {
    backgroundColor: 'rgba(108,60,225,0.15)', borderRadius: RADIUS.full,
    paddingHorizontal: SPACING.sm, paddingVertical: 4,
    borderWidth: 1, borderColor: 'rgba(108,60,225,0.3)',
  },
  prefChipText: { color: COLORS.secondary, fontSize: FONTS.sizes.xs, fontWeight: '600', textTransform: 'capitalize' },
  section: { marginHorizontal: SPACING.lg, marginBottom: SPACING.md },
  sectionTitle: { color: COLORS.textSecondary, fontSize: FONTS.sizes.sm, fontWeight: '600', letterSpacing: 0.5, marginBottom: SPACING.sm },
  menuCard: { backgroundColor: COLORS.surface, borderRadius: RADIUS.xl, borderWidth: 1, borderColor: COLORS.border, overflow: 'hidden' },
  menuItem: { flexDirection: 'row', alignItems: 'center', padding: SPACING.md, gap: SPACING.md },
  menuItemBorder: { borderBottomWidth: 1, borderBottomColor: COLORS.border },
  menuIcon: { width: 36, height: 36, borderRadius: RADIUS.md, backgroundColor: COLORS.surfaceLight, alignItems: 'center', justifyContent: 'center' },
  menuIconAccent: { backgroundColor: 'rgba(245,166,35,0.15)' },
  menuLabel: { color: COLORS.text, fontSize: FONTS.sizes.md, flex: 1 },
  menuLabelAccent: { color: COLORS.accent },
  adminBtn: {
    flexDirection: 'row', alignItems: 'center', gap: SPACING.sm,
    marginHorizontal: SPACING.lg, marginBottom: SPACING.md,
    backgroundColor: COLORS.secondary, borderRadius: RADIUS.xl, padding: SPACING.md,
  },
  adminBtnText: { color: COLORS.white, fontSize: FONTS.sizes.md, fontWeight: '700', flex: 1 },
  signOutBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: SPACING.sm,
    marginHorizontal: SPACING.lg, backgroundColor: 'rgba(244,67,54,0.08)',
    borderRadius: RADIUS.xl, padding: SPACING.md, borderWidth: 1, borderColor: 'rgba(244,67,54,0.2)',
  },
  signOutText: { color: COLORS.error, fontSize: FONTS.sizes.md, fontWeight: '600' },
});
