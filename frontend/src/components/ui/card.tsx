import * as React from 'react';

type DivProps = React.HTMLAttributes<HTMLDivElement>;

export function Card({ className = '', ...props }: DivProps) {
  return <div className={`rounded-lg border border-slate-200 bg-white shadow-sm ${className}`.trim()} {...props} />;
}

export function CardHeader({ className = '', ...props }: DivProps) {
  return <div className={`p-6 ${className}`.trim()} {...props} />;
}

export function CardTitle({ className = '', ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={`font-semibold leading-none tracking-tight ${className}`.trim()} {...props} />;
}

export function CardDescription({ className = '', ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={`text-sm text-slate-600 ${className}`.trim()} {...props} />;
}

export function CardContent({ className = '', ...props }: DivProps) {
  return <div className={`px-6 pb-6 ${className}`.trim()} {...props} />;
}
