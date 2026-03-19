export interface User {
  id: number;
  name: string;
  email: string;
  role: string;
  preferences?: UserPreferences;
  membership?: Membership;
}

export interface UserPreferences {
  cuisines: string[];
  activities: string[];
  travelStyle: string;
  budgetTier: string;
  dietaryRestrictions: string[];
  accommodation: string;
  companions: string;
  pacePreference: string;
}

export interface Membership {
  id: number;
  type: 'explorer' | 'voyager' | 'elite';
  expiresAt: string;
  status: 'active' | 'expired' | 'cancelled';
}

export interface TravelPackage {
  id: string;
  destination: string;
  country: string;
  startDate: string;
  endDate: string;
  duration: number;
  coverImage: string;
  price: number;
  originalPrice?: number;
  rating: number;
  reviewCount: number;
  badge?: string;
  isAIGenerated: boolean;
  summary: string;
  itinerary: ItineraryDay[];
  included: string[];
  highlights: string[];
  flight?: FlightInfo;
  hotel?: HotelInfo;
}

export interface ItineraryDay {
  day: number;
  date: string;
  title: string;
  description: string;
  activities: Activity[];
  meals: Meal[];
  accommodation?: string;
}

export interface Activity {
  id: string;
  name: string;
  type: string;
  duration: string;
  description: string;
  icon: string;
  price?: number;
}

export interface Meal {
  type: 'breakfast' | 'lunch' | 'dinner';
  restaurant: string;
  cuisine: string;
  description: string;
  priceRange: string;
}

export interface FlightInfo {
  outbound: FlightLeg;
  return: FlightLeg;
  class: string;
}

export interface FlightLeg {
  airline: string;
  flightNumber: string;
  departure: string;
  arrival: string;
  duration: string;
  stops: number;
}

export interface HotelInfo {
  name: string;
  stars: number;
  location: string;
  description: string;
  amenities: string[];
  checkIn: string;
  checkOut: string;
}

export interface SubscriptionPlan {
  id: string;
  name: string;
  price: number;
  period: 'month' | 'year';
  features: string[];
  highlighted?: boolean;
  color: string;
}

export interface Deal {
  id: number;
  title: string;
  location: string;
  startDate: string;
  endDate: string;
  price: number;
  rating: number;
  imageUrl: string;
  badge?: string;
  description: string;
  activities: string;
}

export type RootStackParamList = {
  Welcome: undefined;
  Login: undefined;
  Register: undefined;
  Onboarding: undefined;
  Main: undefined;
  PackageDetail: { packageId: string };
  GeneratePackage: undefined;
  Plans: undefined;
  Payment: { planId: string; isOneTime?: boolean; packageId?: string };
};

export interface RequestedPackage {
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
}

export type MainTabParamList = {
  Home: undefined;
  AIChat: undefined;
  Generate: undefined;
  Trips: undefined;
  Profile: undefined;
};
