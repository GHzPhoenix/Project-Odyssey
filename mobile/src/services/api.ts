import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

const BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'https://project-odyssey-production.up.railway.app/api';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
});

api.interceptors.request.use(async (config) => {
  const token = await AsyncStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const msg = error.response?.data?.error || '';
    // Clear token if unauthorized OR if the token is invalid/expired
    if (status === 401 || (status === 403 && msg === 'Invalid token')) {
      AsyncStorage.removeItem('token');
    }
    return Promise.reject(error);
  }
);

// Auth
export const authAPI = {
  register: (name: string, email: string, password: string) =>
    api.post('/register', { name, email, password }),
  login: (email: string, password: string) =>
    api.post('/login', { email, password }),
};

// Preferences
export const preferencesAPI = {
  save: (preferences: any) => api.post('/preferences', preferences),
  get: () => api.get('/preferences'),
};

// Deals / Packages
export const packagesAPI = {
  getFeatured: () => api.get('/deals'),
  getById: (id: string) => api.get(`/deals/${id}`),
  getGenerated: (id: string) => api.get(`/packages/${id}`),
  getMyRequests: () => api.get('/packages/my-requests'),
  generate: (params: {
    destination: string;
    startDate: string;
    endDate: string;
    guests: number;
    departureLocation?: string;
  }) => api.post('/packages/generate', params),
};

// Membership / Subscriptions
export const subscriptionAPI = {
  getPlans: () => api.get('/subscription/plans'),
  subscribe: (planId: string, billingPeriod: 'monthly' | 'yearly') =>
    api.post('/subscription/subscribe', { planId, billingPeriod }),
  getSubscription: () => api.get('/subscription'),
  getMembership: () => api.get('/membership'),
};

// Bookings
export const bookingsAPI = {
  create: (params: {
    deal_id: number;
    destination: string;
    start_date: string;
    end_date: string;
    guests: number;
  }) => api.post('/bookings', params),
  getMyBookings: () => api.get('/bookings'),
  cancel: (bookingId: number) => api.patch(`/bookings/${bookingId}/cancel`),
};

// User profile
export const userAPI = {
  updateProfile: (data: { name?: string; email?: string }) =>
    api.put('/users/profile', data),
};

// Stripe
export const stripeAPI = {
  getConfig: () => api.get('/config/stripe'),
  createPaymentIntent: (planId: string, billingPeriod: 'monthly' | 'yearly') =>
    api.post('/stripe/create-payment-intent', { planId, billingPeriod }),
  createTripPaymentIntent: (packageId: number) =>
    api.post('/stripe/create-trip-payment-intent', { packageId }),
};

// AI Chat
export const chatAPI = {
  sendMessage: (messages: { role: 'user' | 'assistant'; content: string }[], packageId?: number) =>
    api.post('/chat', { messages, packageId }),
};

// Push notifications
export const pushAPI = {
  saveToken: (token: string) => api.post('/push-token', { token }),
};

// Admin
export const adminAPI = {
  getAllPackages: () => api.get('/admin/packages'),
  markReady: (packageId: number, price: number) =>
    api.put(`/packages/${packageId}/ready`, { price }),
};

export default api;
