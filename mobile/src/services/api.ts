import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

const BASE_URL = 'http://localhost:5001/api';

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
    if (error.response?.status === 401) {
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

// Packages / Deals
export const packagesAPI = {
  getFeatured: () => api.get('/deals'),
  getById: (id: string) => api.get(`/deals/${id}`),
  generate: (params: {
    destination: string;
    startDate: string;
    endDate: string;
    guests: number;
  }) => api.post('/packages/generate', params),
};

// Membership / Subscriptions
export const subscriptionAPI = {
  getPlans: () => api.get('/subscription/plans'),
  subscribe: (planId: string) => api.post('/subscription/subscribe', { planId }),
  getMembership: () => api.get('/membership'),
  purchaseOneTime: (packageId: string) =>
    api.post('/packages/purchase', { packageId }),
};

// Bookings
export const bookingsAPI = {
  create: (packageId: string, guests: number) =>
    api.post('/bookings', { packageId, guests }),
  getMyBookings: () => api.get('/bookings'),
  cancel: (bookingId: number) => api.patch(`/bookings/${bookingId}/cancel`),
};

export default api;
