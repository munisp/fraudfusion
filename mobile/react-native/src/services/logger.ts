export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogContext = Record<string, unknown>;

export interface LogEvent {
  level: LogLevel;
  event: string;
  context?: LogContext;
  timestamp: string;
}

declare global {
  var __FRAUDFUSION_LOG_SINK__: ((event: LogEvent) => void) | undefined;
}

const sensitiveKeys = new Set([
  'authorization',
  'access_token',
  'accesstoken',
  'refresh_token',
  'refreshtoken',
  'token',
  'password',
  'bvn',
  'nin',
  'documentnumber',
  'biometricdata',
]);

function redact(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redact);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        sensitiveKeys.has(key.toLowerCase()) ? '[REDACTED]' : redact(item),
      ]),
    );
  }
  return value;
}

function emit(level: LogLevel, event: string, context?: LogContext): void {
  const sink = globalThis.__FRAUDFUSION_LOG_SINK__;
  if (!sink) {
    return;
  }
  sink({
    level,
    event,
    context: context ? (redact(context) as LogContext) : undefined,
    timestamp: new Date().toISOString(),
  });
}

export const logger = {
  debug: (event: string, context?: LogContext): void => emit('debug', event, context),
  info: (event: string, context?: LogContext): void => emit('info', event, context),
  warn: (event: string, context?: LogContext): void => emit('warn', event, context),
  error: (event: string, context?: LogContext): void => emit('error', event, context),
};
