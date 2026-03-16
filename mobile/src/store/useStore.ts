import { create } from 'zustand';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { User, TravelPackage, UserPreferences } from '../types';

interface AppState {
  // Auth
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isOnboardingComplete: boolean;

  // Packages
  savedPackages: TravelPackage[];
  myTrips: TravelPackage[];
  featuredDeals: any[];

  // UI
  isLoading: boolean;

  // Actions
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  setOnboardingComplete: (complete: boolean) => void;
  updatePreferences: (prefs: UserPreferences) => void;
  savePackage: (pkg: TravelPackage) => void;
  unsavePackage: (id: string) => void;
  addTrip: (pkg: TravelPackage) => void;
  setFeaturedDeals: (deals: any[]) => void;
  setLoading: (loading: boolean) => void;
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
  featuredDeals: [],
  isLoading: false,

  setUser: (user) => set({ user, isAuthenticated: !!user }),

  setToken: async (token) => {
    set({ token });
    if (token) {
      await AsyncStorage.setItem('token', token);
    } else {
      await AsyncStorage.removeItem('token');
    }
  },

  setOnboardingComplete: async (complete) => {
    set({ isOnboardingComplete: complete });
    await AsyncStorage.setItem('onboardingComplete', complete ? 'true' : 'false');
  },

  updatePreferences: (prefs) => {
    const user = get().user;
    if (user) {
      set({ user: { ...user, preferences: prefs } });
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

  setFeaturedDeals: (deals) => set({ featuredDeals: deals }),

  setLoading: (loading) => set({ isLoading: loading }),

  logout: async () => {
    await AsyncStorage.removeItem('token');
    await AsyncStorage.removeItem('user');
    set({
      user: null,
      token: null,
      isAuthenticated: false,
      savedPackages: [],
      myTrips: [],
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
