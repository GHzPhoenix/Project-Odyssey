import { create } from 'zustand';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { User, TravelPackage, UserPreferences, Membership, RequestedPackage } from '../types';

export interface BookingItem {
  id: number;
  deal_id: number;
  destination: string;
  start_date: string;
  end_date: string;
  guests: number;
  cancelled_at: string | null;
  created_at?: string;
}

interface AppState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isOnboardingComplete: boolean;
  savedPackages: TravelPackage[];
  myTrips: TravelPackage[];
  myBookings: BookingItem[];
  featuredDeals: any[];
  isLoading: boolean;
  requestedPackages: RequestedPackage[];
  unreadCount: number;

  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  setOnboardingComplete: (complete: boolean) => void;
  updatePreferences: (prefs: UserPreferences) => void;
  setMembership: (membership: Membership | null) => void;
  savePackage: (pkg: TravelPackage) => void;
  unsavePackage: (id: string) => void;
  addTrip: (pkg: TravelPackage) => void;
  setMyTrips: (trips: TravelPackage[]) => void;
  setMyBookings: (bookings: BookingItem[]) => void;
  setFeaturedDeals: (deals: any[]) => void;
  setLoading: (loading: boolean) => void;
  setRequestedPackages: (pkgs: RequestedPackage[]) => void;
  logout: () => void;
  loadFromStorage: () => Promise<void>;
}

export const useStore = create<AppState>((set, get) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  isOnboardingComplete: false,
  savedPackages: [],
  myTrips: [],
  myBookings: [],
  featuredDeals: [],
  isLoading: false,
  requestedPackages: [],
  unreadCount: 0,

  setUser: (user) => {
    set({ user, isAuthenticated: !!user });
    if (user) AsyncStorage.setItem('user', JSON.stringify(user));
    else AsyncStorage.removeItem('user');
  },

  setToken: async (token) => {
    set({ token });
    if (token) await AsyncStorage.setItem('token', token);
    else await AsyncStorage.removeItem('token');
  },

  setOnboardingComplete: async (complete) => {
    set({ isOnboardingComplete: complete });
    await AsyncStorage.setItem('onboardingComplete', complete ? 'true' : 'false');
  },

  updatePreferences: (prefs) => {
    const user = get().user;
    if (user) {
      const updated = { ...user, preferences: prefs };
      set({ user: updated });
      AsyncStorage.setItem('user', JSON.stringify(updated));
    }
  },

  setMembership: (membership) => {
    const user = get().user;
    if (user) {
      const updated = { ...user, membership: membership ?? undefined };
      set({ user: updated });
      AsyncStorage.setItem('user', JSON.stringify(updated));
    }
  },

  savePackage: (pkg) => {
    const saved = get().savedPackages;
    if (!saved.find((p) => p.id === pkg.id)) {
      set({ savedPackages: [...saved, pkg] });
    }
  },

  unsavePackage: (id) => {
    set({ savedPackages: get().savedPackages.filter((p) => p.id !== id) });
  },

  addTrip: (pkg) => {
    const trips = get().myTrips;
    if (!trips.find((t) => t.id === pkg.id)) {
      set({ myTrips: [...trips, pkg] });
    }
  },

  setMyTrips: (trips) => set({ myTrips: trips }),

  setMyBookings: (bookings) => set({ myBookings: bookings }),

  setFeaturedDeals: (deals) => set({ featuredDeals: deals }),

  setLoading: (loading) => set({ isLoading: loading }),

  setRequestedPackages: (pkgs) => set({
    requestedPackages: pkgs,
    unreadCount: pkgs.filter((p) => p.status === 'ready').length,
  }),

  logout: async () => {
    await AsyncStorage.removeItem('token');
    await AsyncStorage.removeItem('user');
    set({
      user: null,
      token: null,
      isAuthenticated: false,
      savedPackages: [],
      myTrips: [],
      myBookings: [],
      requestedPackages: [],
      unreadCount: 0,
    });
  },

  loadFromStorage: async () => {
    const token = await AsyncStorage.getItem('token');
    const userStr = await AsyncStorage.getItem('user');
    const onboarding = await AsyncStorage.getItem('onboardingComplete');
    if (token) set({ token });
    if (userStr) {
      try {
        const user = JSON.parse(userStr);
        set({ user, isAuthenticated: true });
      } catch {}
    }
    if (onboarding === 'true') set({ isOnboardingComplete: true });
  },
}));
