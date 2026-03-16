// Dynamic Expo config — reads environment variables at build time.
// Values set here override the static app.json for the matching keys.
// EAS Build injects EXPO_PUBLIC_* vars from eas.json build.env.

module.exports = ({ config }) => ({
  ...config,
  extra: {
    ...config.extra,
    apiUrl: process.env.EXPO_PUBLIC_API_URL || 'http://localhost:5001/api',
    eas: {
      projectId: process.env.EAS_PROJECT_ID || 'YOUR_EAS_PROJECT_ID',
    },
  },
});
