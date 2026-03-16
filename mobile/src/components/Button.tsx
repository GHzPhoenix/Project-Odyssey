import React from 'react';
import {
  TouchableOpacity,
  Text,
  StyleSheet,
  ActivityIndicator,
  ViewStyle,
  TextStyle,
} from 'react-native';
import { COLORS, FONTS, SPACING, RADIUS, SHADOWS } from '../constants/theme';

interface Props {
  label: string;
  onPress: () => void;
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  disabled?: boolean;
  style?: ViewStyle;
  textStyle?: TextStyle;
  fullWidth?: boolean;
}

export const Button: React.FC<Props> = ({
  label,
  onPress,
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled = false,
  style,
  textStyle,
  fullWidth = true,
}) => {
  const getContainerStyle = (): ViewStyle => {
    const base: ViewStyle = {
      borderRadius: RADIUS.full,
      alignItems: 'center',
      justifyContent: 'center',
      flexDirection: 'row',
      paddingVertical: size === 'sm' ? SPACING.sm : size === 'lg' ? SPACING.lg : SPACING.md,
      paddingHorizontal: size === 'sm' ? SPACING.md : size === 'lg' ? SPACING.xxl : SPACING.xl,
    };

    if (fullWidth) base.width = '100%';

    switch (variant) {
      case 'primary':
        return { ...base, backgroundColor: COLORS.secondary, ...SHADOWS.md };
      case 'secondary':
        return { ...base, backgroundColor: COLORS.accent, ...SHADOWS.sm };
      case 'outline':
        return { ...base, borderWidth: 1.5, borderColor: COLORS.secondary };
      case 'ghost':
        return { ...base };
      default:
        return base;
    }
  };

  const getTextStyle = (): TextStyle => {
    const base: TextStyle = {
      fontWeight: '700',
      letterSpacing: 0.5,
      fontSize: size === 'sm' ? FONTS.sizes.sm : size === 'lg' ? FONTS.sizes.lg : FONTS.sizes.md,
    };

    switch (variant) {
      case 'primary':
        return { ...base, color: COLORS.white };
      case 'secondary':
        return { ...base, color: COLORS.primary };
      case 'outline':
        return { ...base, color: COLORS.secondary };
      case 'ghost':
        return { ...base, color: COLORS.textSecondary };
      default:
        return base;
    }
  };

  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={disabled || loading}
      style={[getContainerStyle(), disabled && styles.disabled, style]}
      activeOpacity={0.8}
    >
      {loading ? (
        <ActivityIndicator color={variant === 'primary' ? COLORS.white : COLORS.secondary} size="small" />
      ) : (
        <Text style={[getTextStyle(), textStyle]}>{label}</Text>
      )}
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  disabled: {
    opacity: 0.5,
  },
});
