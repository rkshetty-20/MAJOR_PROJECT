import React from 'react';
import { Loader2 } from 'lucide-react';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  fullWidth?: boolean;
}

const VARIANT: Record<ButtonVariant, string> = {
  primary:
    'bg-accent text-white border border-accent hover:bg-accent/90 focus-visible:ring-accent/40 disabled:hover:bg-accent',
  secondary:
    'bg-elevated text-ink border border-line-strong hover:bg-elevated/70 focus-visible:ring-accent/30',
  ghost:
    'bg-transparent text-ink-muted border border-transparent hover:text-ink hover:bg-elevated/60 focus-visible:ring-accent/25',
  danger:
    'bg-danger/15 text-danger border border-danger/40 hover:bg-danger/25 focus-visible:ring-danger/40',
};

const SIZE: Record<ButtonSize, string> = {
  sm: 'text-xs px-2.5 py-1.5 gap-1.5 rounded-lg',
  md: 'text-sm px-3.5 py-2 gap-2 rounded-lg',
  lg: 'text-sm px-4 py-2.5 gap-2 rounded-xl',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  leftIcon,
  rightIcon,
  fullWidth,
  className = '',
  disabled,
  children,
  type = 'button',
  ...rest
}) => {
  const isDisabled = disabled || loading;
  return (
    <button
      type={type}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      className={[
        'inline-flex items-center justify-center font-medium transition-colors duration-base',
        'focus:outline-none focus-visible:outline-none focus-visible:ring-2 disabled:opacity-55 disabled:cursor-not-allowed',
        VARIANT[variant],
        SIZE[size],
        fullWidth ? 'w-full' : '',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      {...rest}
    >
      {loading ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : leftIcon}
      {children}
      {!loading && rightIcon}
    </button>
  );
};
