/**
 * Journey Management Dashboard
 *
 * Aligned to the orchestrator's real routes (orchestrator/go):
 *   POST /api/v1/journey/execute            — start ExecuteJourneyWorkflow
 *   GET  /api/v1/journey/executions/{id}    — poll execution status/result
 *
 * The orchestrator exposes no journey catalog or analytics endpoints, so this
 * dashboard ships a static catalog of known journeys and tracks only the
 * executions started from (or looked up in) this session. No metrics are
 * fabricated: anything the API does not return is simply not shown.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import {
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  RefreshCw,
  Activity
} from 'lucide-react';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

async function fetchApi<T>(path: string, init?: RequestInit, signal?: AbortSignal): Promise<T> {
  const token = localStorage.getItem('auth_token');
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
    credentials: 'same-origin',
    // 10s client-side timeout; also aborts when the caller (unmounted view) cancels.
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.json();
      detail = body?.error ? `: ${body.error}` : '';
    } catch {
      // Non-JSON error body; keep the status-only message.
    }
    throw new Error(`Journey API request failed with status ${response.status}${detail}.`);
  }
  return response.json() as Promise<T>;
}

// --- Contract types (mirror orchestrator/go/cmd/orchestrator/main.go) ---

interface StepExecution {
  step_id: string;
  name: string;
  status: string;
  duration?: number;
  error?: string;
  output?: unknown;
}

// JourneyExecution as returned by GET /api/v1/journey/executions/{id}.
interface JourneyExecution {
  execution_id: string;
  journey_id: string;
  user_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  steps: StepExecution[] | null;
  result?: unknown;
  error?: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

// Response of POST /api/v1/journey/execute (202 Accepted).
interface ExecuteJourneyResponse {
  execution_id: string;
  workflow_id: string;
  run_id: string;
  journey_id: string;
  status: string;
  started_at: string;
  poll_url: string;
}

// Static catalog of the journeys the Temporal worker actually registers.
// (The orchestrator has no catalog endpoint; journey metadata lives with the
// worker — services/go/temporal-orchestrator/workflows.)
interface CatalogEntry {
  id: string;
  name: string;
  description: string;
}

const JOURNEY_CATALOG: CatalogEntry[] = [
  {
    id: 'journey-34',
    name: 'Land Double Allocation Detection',
    description: 'Detects multiple claimants, court disputes and unauthorized sellers for a property.',
  },
  {
    id: 'journey-37',
    name: 'Professional Consultation Booking',
    description: 'Searches the professional directory, checks availability and books a consultation.',
  },
];

const TERMINAL_STATUSES = new Set(['completed', 'failed']);

function statusBadgeVariant(status: string): 'default' | 'destructive' | 'secondary' | 'outline' {
  switch (status) {
    case 'completed':
      return 'default';
    case 'failed':
      return 'destructive';
    case 'running':
      return 'secondary';
    default:
      return 'outline';
  }
}

const JourneyDashboard: React.FC = () => {
  const [executions, setExecutions] = useState<Record<string, JourneyExecution>>({});
  const [executeJourneyId, setExecuteJourneyId] = useState<string>(JOURNEY_CATALOG[0].id);
  const [executeUserId, setExecuteUserId] = useState<string>('');
  const [executeData, setExecuteData] = useState<string>('{}');
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [executing, setExecuting] = useState<boolean>(false);
  const [lookupId, setLookupId] = useState<string>('');
  const [lookupError, setLookupError] = useState<string | null>(null);
  const mountedRef = useRef<boolean>(true);
  const pollersRef = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  useEffect(() => {
    mountedRef.current = true;
    const pollers = pollersRef.current;
    return () => {
      mountedRef.current = false;
      pollers.forEach((handle) => clearInterval(handle));
      pollers.clear();
    };
  }, []);

  const stopPolling = useCallback((executionId: string) => {
    const handle = pollersRef.current.get(executionId);
    if (handle) {
      clearInterval(handle);
      pollersRef.current.delete(executionId);
    }
  }, []);

  // pollExecution follows GET /api/v1/journey/executions/{id} until the
  // execution reaches a terminal state.
  const pollExecution = useCallback(async (executionId: string) => {
    try {
      const execution = await fetchApi<JourneyExecution>(`/api/v1/journey/executions/${executionId}`);
      if (!mountedRef.current) return;
      setExecutions((prev) => ({ ...prev, [executionId]: execution }));
      if (TERMINAL_STATUSES.has(execution.status)) {
        stopPolling(executionId);
      }
    } catch {
      // Transient poll failure: keep polling; the last known state stays on screen.
    }
  }, [stopPolling]);

  const startPolling = useCallback((executionId: string) => {
    stopPolling(executionId);
    pollersRef.current.set(executionId, setInterval(() => void pollExecution(executionId), 2_000));
    void pollExecution(executionId);
  }, [pollExecution, stopPolling]);

  const executeJourney = async () => {
    setExecuteError(null);
    let data: Record<string, unknown>;
    try {
      data = executeData.trim() === '' ? {} : JSON.parse(executeData);
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        throw new Error('not an object');
      }
    } catch {
      setExecuteError('Journey data must be a valid JSON object.');
      return;
    }
    setExecuting(true);
    try {
      const response = await fetchApi<ExecuteJourneyResponse>('/api/v1/journey/execute', {
        method: 'POST',
        body: JSON.stringify({
          journey_id: executeJourneyId,
          user_id: executeUserId,
          data,
        }),
      });
      startPolling(response.execution_id);
    } catch (error) {
      setExecuteError(error instanceof Error ? error.message : 'Failed to start journey.');
    } finally {
      if (mountedRef.current) {
        setExecuting(false);
      }
    }
  };

  const lookupExecution = async () => {
    setLookupError(null);
    const id = lookupId.trim();
    if (!id) return;
    try {
      const execution = await fetchApi<JourneyExecution>(`/api/v1/journey/executions/${id}`);
      setExecutions((prev) => ({ ...prev, [id]: execution }));
      if (!TERMINAL_STATUSES.has(execution.status)) {
        startPolling(id);
      }
    } catch (error) {
      setLookupError(error instanceof Error ? error.message : 'Execution not found.');
    }
  };

  const trackedExecutions = Object.values(executions).sort((a, b) => b.created_at.localeCompare(a.created_at));
  const activeCount = trackedExecutions.filter((e) => !TERMINAL_STATUSES.has(e.status)).length;

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Journey Management Dashboard</h1>
          <p className="text-muted-foreground mt-2">
            Execute and monitor journeys via the orchestrator (Temporal-backed).
          </p>
        </div>

        {/* Overview Cards — only session-real numbers, nothing fabricated */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Available Journeys</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{JOURNEY_CATALOG.length}</div>
              <p className="text-xs text-muted-foreground mt-1">Registered with the Temporal worker</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Tracked Executions</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{trackedExecutions.length}</div>
              <p className="text-xs text-muted-foreground mt-1">This session</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Active Now</CardTitle>
              <Activity className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{activeCount}</div>
              <p className="text-xs text-muted-foreground mt-1">Polling every 2s</p>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="execute" className="space-y-4">
          <TabsList>
            <TabsTrigger value="execute">Execute Journey</TabsTrigger>
            <TabsTrigger value="executions">Executions ({trackedExecutions.length})</TabsTrigger>
          </TabsList>

          {/* Execute Tab */}
          <TabsContent value="execute" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {JOURNEY_CATALOG.map((journey) => (
                <Card key={journey.id} className={executeJourneyId === journey.id ? 'border-primary' : ''}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-lg">{journey.name}</CardTitle>
                        <CardDescription className="mt-1">{journey.description}</CardDescription>
                      </div>
                      <Badge variant="outline">{journey.id}</Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Button size="sm" variant={executeJourneyId === journey.id ? 'default' : 'outline'}
                      onClick={() => setExecuteJourneyId(journey.id)}>
                      <Play className="h-4 w-4 mr-1" />
                      {executeJourneyId === journey.id ? 'Selected' : 'Select'}
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Start Execution</CardTitle>
                <CardDescription>
                  POST /api/v1/journey/execute — starts ExecuteJourneyWorkflow on the Temporal worker.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="journey-user" className="text-sm font-medium">User ID</label>
                  <Input id="journey-user" placeholder="user-123" value={executeUserId}
                    onChange={(e) => setExecuteUserId(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <label htmlFor="journey-data" className="text-sm font-medium">Journey Data (JSON)</label>
                  <textarea id="journey-data" rows={6} value={executeData}
                    onChange={(e) => setExecuteData(e.target.value)}
                    className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                    placeholder='{"steps": [...], "document_file": "..."}' />
                </div>
                {executeError && (
                  <div className="flex items-center gap-2 text-destructive text-sm">
                    <AlertCircle className="h-4 w-4" />
                    {executeError}
                  </div>
                )}
                <Button onClick={() => void executeJourney()} disabled={executing}>
                  {executing ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                  Execute {executeJourneyId}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Executions Tab */}
          <TabsContent value="executions" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Track an Execution</CardTitle>
                <CardDescription>
                  Look up any execution by ID (GET /api/v1/journey/executions/{'{id}'}).
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex gap-2">
                  <Input placeholder="exec-..." value={lookupId} onChange={(e) => setLookupId(e.target.value)}
                    className="max-w-sm" />
                  <Button variant="outline" onClick={() => void lookupExecution()}>Track</Button>
                </div>
                {lookupError && (
                  <div className="flex items-center gap-2 text-destructive text-sm">
                    <AlertCircle className="h-4 w-4" />
                    {lookupError}
                  </div>
                )}
              </CardContent>
            </Card>

            {trackedExecutions.length === 0 ? (
              <Card>
                <CardContent className="py-8 text-center text-muted-foreground">
                  No executions tracked yet — start one from the Execute tab or track by ID.
                </CardContent>
              </Card>
            ) : (
              trackedExecutions.map((execution) => (
                <Card key={execution.execution_id}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg">{execution.journey_id}</CardTitle>
                        <CardDescription>
                          {execution.execution_id} · user {execution.user_id || '—'}
                        </CardDescription>
                      </div>
                      <Badge variant={statusBadgeVariant(execution.status)}>
                        {execution.status === 'completed' && <CheckCircle2 className="h-3 w-3 mr-1" />}
                        {execution.status === 'failed' && <XCircle className="h-3 w-3 mr-1" />}
                        {!TERMINAL_STATUSES.has(execution.status) && <RefreshCw className="h-3 w-3 mr-1 animate-spin" />}
                        {execution.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {execution.error && (
                      <div className="flex items-center gap-2 text-destructive text-sm">
                        <AlertCircle className="h-4 w-4" />
                        {execution.error}
                      </div>
                    )}
                    {execution.steps && execution.steps.length > 0 && (
                      <div className="space-y-2">
                        {execution.steps.map((step) => (
                          <div key={step.step_id} className="flex items-center justify-between text-sm border rounded px-3 py-2">
                            <span>{step.name || step.step_id}</span>
                            <span className="flex items-center gap-2">
                              {step.duration !== undefined && (
                                <span className="text-muted-foreground">{step.duration}ms</span>
                              )}
                              <Badge variant={statusBadgeVariant(step.status)}>{step.status}</Badge>
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                    {execution.result != null && (
                      <pre className="text-xs bg-muted rounded p-3 overflow-auto max-h-64">
                        {JSON.stringify(execution.result, null, 2)}
                      </pre>
                    )}
                    <div className="text-xs text-muted-foreground">
                      Started {new Date(execution.created_at).toLocaleString()}
                      {execution.completed_at ? ` · Completed ${new Date(execution.completed_at).toLocaleString()}` : ''}
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default JourneyDashboard;
