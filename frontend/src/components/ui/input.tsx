import * as React from 'react';

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className = '', type = 'text', ...props }, ref) => (
    <input
      ref={ref}
      type={type}
      className={`flex h-10 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-400 disabled:cursor-not-allowed disabled:opacity-50 ${className}`.trim()}
      {...props}
    />
  ),
);

Input.displayName = 'Input';
