import * as React from 'react';

type TabsContextValue = {
  value: string;
  setValue: (value: string) => void;
};

const TabsContext = React.createContext<TabsContextValue | null>(null);

function useTabsContext() {
  const context = React.useContext(TabsContext);
  if (!context) {
    throw new Error('Tabs components must be nested inside Tabs.');
  }
  return context;
}

export function Tabs({ defaultValue, value, onValueChange, className = '', children }: {
  defaultValue: string;
  value?: string;
  onValueChange?: (value: string) => void;
  className?: string;
  children: React.ReactNode;
}) {
  const [internalValue, setInternalValue] = React.useState(defaultValue);
  const selectedValue = value ?? internalValue;
  const setValue = (nextValue: string) => {
    if (value === undefined) setInternalValue(nextValue);
    onValueChange?.(nextValue);
  };
  return <TabsContext.Provider value={{ value: selectedValue, setValue }}><div className={className}>{children}</div></TabsContext.Provider>;
}

export function TabsList({ className = '', ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div role="tablist" className={`inline-flex rounded-md bg-slate-100 p-1 ${className}`.trim()} {...props} />;
}

export function TabsTrigger({ value, className = '', children }: { value: string; className?: string; children: React.ReactNode }) {
  const tabs = useTabsContext();
  const selected = tabs.value === value;
  return (
    <button
      type="button"
      role="tab"
      aria-selected={selected}
      onClick={() => tabs.setValue(value)}
      className={`rounded px-3 py-1.5 text-sm font-medium ${selected ? 'bg-white text-slate-950 shadow-sm' : 'text-slate-600 hover:text-slate-950'} ${className}`.trim()}
    >
      {children}
    </button>
  );
}

export function TabsContent({ value, className = '', children }: { value: string; className?: string; children: React.ReactNode }) {
  const tabs = useTabsContext();
  if (tabs.value !== value) return null;
  return <div role="tabpanel" className={className}>{children}</div>;
}
