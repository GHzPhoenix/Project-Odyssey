import React from 'react';
import { View, StyleSheet, ViewStyle } from 'react-native';
import { COLORS } from '../constants/theme';

interface Props {
  children: React.ReactNode;
  style?: ViewStyle;
  variant?: 'primary' | 'hero' | 'card';
}

export const GradientBackground: React.FC<Props> = ({ children, style, variant = 'primary' }) => {
  return (
    <View style={[styles.container, { backgroundColor: COLORS.background }, style]}>
      {children}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});
