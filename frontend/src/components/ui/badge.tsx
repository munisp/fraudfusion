import * as React from 'react';

type BadgeVariant = 'default' | 'secondary' | 'outline' | 'destructive';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

const variants: Record<BadgeVariant, string> = {
  default: 'bg-slate-900 text-white',
  secondary: 'bg-slate-100 text-slate-800',
  outline: 'border border-slate-300 bg-white text-slate-800',
  destructive: 'bg-red-100 text-red-800',
};

export function Badge({ className = '', variant = 'default', ...props }: BadgeProps) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${variants[variant]} ${className}`.trim()} {...props} />;
}
