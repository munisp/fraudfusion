/**
 * Journey Management Dashboard
 * Admin interface for managing and monitoring all 30 user journeys
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import {
  Play,
  Pause,
  BarChart3,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  TrendingUp,
  Users,
  Activity
} from 'lucide-react';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

async function fetchApi<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = localStorage.getItem('auth_token');
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}`, Accept: 'application/json' } : { Accept: 'application/json' },
    credentials: 'same-origin',
    // 10s client-side timeout; also aborts when the caller (unmounted view) cancels.
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`Journey API request failed with status ${response.status}.`);
  }
  return response.json() as Promise<T>;
}

// Types
interface Journey {
  id: string;
  name: string;
  description: string;
  sector: string;
  steps: number;
  avg_duration_seconds: number;
  enabled: boolean;
  pricing_tier: string;
  required_parameters: string[];
}

interface JourneyExecution {
  execution_id: string;
  journey_id: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  progress_percent: number;
  started_at: string;
  user_id: string;
}

interface JourneyAnalytics {
  journey_id: string;
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  success_rate: number;
  avg_duration_seconds: number;
}

const JourneyDashboard: React.FC = () => {
  const [journeys, setJourneys] = useState<Journey[]>([]);
  const [executions, setExecutions] = useState<JourneyExecution[]>([]);
  const [analytics, setAnalytics] = useState<Record<string, JourneyAnalytics>>({});
  const [selectedSector, setSelectedSector] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void loadDashboard(controller.signal);
    // Cancel in-flight requests when the dashboard unmounts.
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadDashboard = async (signal?: AbortSignal) => {
    setLoading(true);
    setLoadError(null);
    try {
      const [journeyData, executionData, analyticsData] = await Promise.all([
        fetchApi<{ journeys: Journey[] }>('/api/v1/journeys', signal),
        fetchApi<{ executions: JourneyExecution[] }>('/api/v1/journeys/executions?status=active', signal),
        fetchApi<{ analytics: JourneyAnalytics[] }>('/api/v1/journeys/analytics', signal),
      ]);
      setJourneys(journeyData.journeys);
      setExecutions(executionData.executions);
      setAnalytics(Object.fromEntries(analyticsData.analytics.map((item) => [item.journey_id, item])));
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return; // Unmounted or superseded load; leave state untouched.
      }
      setJourneys([]);
      setExecutions([]);
      setAnalytics({});
      setLoadError(error instanceof Error ? error.message : 'Unable to load journey data.');
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
    }
  };

  if (loading) {
    return <div className="min-h-screen bg-background p-6 text-muted-foreground">Loading authenticated journey data…</div>;
  }

  if (loadError) {
    return <div className="min-h-screen bg-background p-6 text-destructive">{loadError}</div>;
  }

  // Filter journeys
  const filteredJourneys = journeys.filter(journey => {
    const matchesSector = selectedSector === 'all' || journey.sector === selectedSector;
    const matchesSearch = journey.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         journey.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSector && matchesSearch;
  });

  // Get sector counts
  const sectorCounts = journeys.reduce((acc, journey) => {
    acc[journey.sector] = (acc[journey.sector] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Calculate overall stats
  const totalExecutions = Object.values(analytics).reduce((sum, a) => sum + a.total_executions, 0);
  const totalSuccess = Object.values(analytics).reduce((sum, a) => sum + a.successful_executions, 0);
  const overallSuccessRate = totalExecutions > 0 ? (totalSuccess / totalExecutions * 100).toFixed(1) : '0';

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold">Journey Management Dashboard</h1>
          <p className="text-muted-foreground mt-2">
            Monitor and manage all 30 user journeys across the platform
          </p>
        </div>

        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Total Journeys</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{journeys.length}</div>
              <p className="text-xs text-muted-foreground mt-1">
                Across 7 sectors
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Total Executions</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalExecutions.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground mt-1">
                +12% from last week
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{overallSuccessRate}%</div>
              <p className="text-xs text-muted-foreground mt-1">
                {totalSuccess.toLocaleString()} successful
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Active Now</CardTitle>
              <Activity className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{executions.length}</div>
              <p className="text-xs text-muted-foreground mt-1">
                In progress
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="journeys" className="space-y-4">
          <TabsList>
            <TabsTrigger value="journeys">Journey Catalog</TabsTrigger>
            <TabsTrigger value="executions">Active Executions</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
          </TabsList>

          {/* Journey Catalog Tab */}
          <TabsContent value="journeys" className="space-y-4">
            {/* Filters */}
            <div className="flex gap-4">
              <Input
                placeholder="Search journeys..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="max-w-sm"
              />
              <div className="flex gap-2">
                <Button
                  variant={selectedSector === 'all' ? 'default' : 'outline'}
                  onClick={() => setSelectedSector('all')}
                  size="sm"
                >
                  All ({journeys.length})
                </Button>
                {Object.entries(sectorCounts).map(([sector, count]) => (
                  <Button
                    key={sector}
                    variant={selectedSector === sector ? 'default' : 'outline'}
                    onClick={() => setSelectedSector(sector)}
                    size="sm"
                  >
                    {sector.replace('_', ' ')} ({count})
                  </Button>
                ))}
              </div>
            </div>

            {/* Journey Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredJourneys.map((journey) => (
                <Card key={journey.id} className="hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <CardTitle className="text-lg">{journey.name}</CardTitle>
                        <CardDescription className="mt-1">
                          {journey.description}
                        </CardDescription>
                      </div>
                      <Badge variant={journey.enabled ? 'default' : 'secondary'}>
                        {journey.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Sector</span>
                      <Badge variant="outline">
                        {journey.sector.replace('_', ' ')}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Steps</span>
                      <span className="font-medium">{journey.steps}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Avg Duration</span>
                      <span className="font-medium">{journey.avg_duration_seconds}s</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Pricing</span>
                      <Badge variant="secondary">{journey.pricing_tier}</Badge>
                    </div>

                    {analytics[journey.id] && (
                      <div className="pt-4 border-t">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Success Rate</span>
                          <span className="font-medium text-green-600">
                            {(analytics[journey.id].success_rate * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-sm mt-2">
                          <span className="text-muted-foreground">Executions</span>
                          <span className="font-medium">
                            {analytics[journey.id]?.total_executions.toLocaleString() ?? '0'}
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="flex gap-2 pt-2">
                      <Button size="sm" className="flex-1">
                        <Play className="h-4 w-4 mr-1" />
                        Execute
                      </Button>
                      <Button size="sm" variant="outline" className="flex-1">
                        <BarChart3 className="h-4 w-4 mr-1" />
                        Analytics
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Active Executions Tab */}
          <TabsContent value="executions" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Active Journey Executions</CardTitle>
                <CardDescription>
                  Real-time monitoring of in-progress journeys
                </CardDescription>
              </CardHeader>
              <CardContent>
                {executions.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No active executions at the moment
                  </div>
                ) : (
                  <div className="space-y-4">
                    {executions.map((execution) => (
                      <div
                        key={execution.execution_id}
                        className="border rounded-lg p-4 space-y-3"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-medium">{execution.journey_id}</div>
                            <div className="text-sm text-muted-foreground">
                              User: {execution.user_id}
                            </div>
                          </div>
                          <Badge
                            variant={
                              execution.status === 'completed' ? 'default' :
                              execution.status === 'failed' ? 'destructive' :
                              'secondary'
                            }
                          >
                            {execution.status}
                          </Badge>
                        </div>
                        <div>
                          <div className="flex items-center justify-between text-sm mb-2">
                            <span>Progress</span>
                            <span className="font-medium">{execution.progress_percent}%</span>
                          </div>
                          <div className="w-full bg-secondary rounded-full h-2">
                            <div
                              className="bg-primary h-2 rounded-full transition-all"
                              style={{ width: `${execution.progress_percent}%` }}
                            />
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-sm text-muted-foreground">
                          <span>Started: {new Date(execution.started_at).toLocaleTimeString()}</span>
                          <Button size="sm" variant="outline">View Details</Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.values(analytics).map((analytic) => {
                const journey = journeys.find(j => j.id === analytic.journey_id);
                if (!journey) return null;

                return (
                  <Card key={analytic.journey_id}>
                    <CardHeader>
                      <CardTitle className="text-lg">{journey.name}</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Total Executions</span>
                        <span className="font-bold">{analytic.total_executions.toLocaleString()}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Success Rate</span>
                        <span className="font-bold text-green-600">
                          {(analytic.success_rate * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Avg Duration</span>
                        <span className="font-bold">{analytic.avg_duration_seconds}s</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Failed</span>
                        <span className="font-bold text-red-600">
                          {analytic.failed_executions}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default JourneyDashboard;
