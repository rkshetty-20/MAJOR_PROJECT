import { useEffect, useState, useCallback } from 'react';
import { Menu, X, Shield } from 'lucide-react';
import api from './api';
import { API_DISPLAY_URL } from './apiBase';
import { OverviewMetrics } from './components/SecurityOverview';
import { SimulationResult } from './components/AttackSimulation';
import { RiskData, DetectionItem } from './components/DetectionRiskOverview';
import { RecentEventsTable, SecurityEventItem } from './components/RecentEventsTable';
import { SecurityEventModal } from './components/SecurityEventModal';
import { DetectionInvestigationModal } from './components/DetectionInvestigationModal';
import { SecurityAssistant } from './components/SecurityAssistant';
import { AdaptiveLearningMetrics } from './components/AdaptiveLearningMetrics';

import { Sidebar, PageId } from './components/Sidebar';
import { DashboardPage } from './components/DashboardPage';
import { PhishingDetectionPage } from './components/PhishingDetectionPage';
import { IntrusionDetectionPage } from './components/IntrusionDetectionPage';
import { AttackSimulationPage } from './components/AttackSimulationPage';
import { ScenarioStudioPage } from './components/ScenarioStudioPage';
import { VisualizationInvestigationPage, InvestigationContext } from './components/VisualizationInvestigationPage';
import { SettingsPage } from './components/SettingsPage';
import { SystemHealthProvider, useSystemHealth } from './hooks/useSystemHealth';
import { ToastProvider } from './components/ui';

function AppShell() {
  const health = useSystemHealth();
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // SOC Telemetry & Dashboard state
  const [overviewMetrics, setOverviewMetrics] = useState<OverviewMetrics | null>(null);
  const [riskData, setRiskData] = useState<RiskData | null>(null);
  const [detections, setDetections] = useState<DetectionItem[]>([]);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [isTelemetryLoading, setIsTelemetryLoading] = useState<boolean>(false);

  // Inspection & Interaction state
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [selectedDetectionId, setSelectedDetectionId] = useState<number | null>(null);
  const [activeSimulationId, setActiveSimulationId] = useState<string | null>(null);
  const [activeScenarioName, setActiveScenarioName] = useState<string | undefined>(undefined);
  const [activeSimulationResult, setActiveSimulationResult] = useState<SimulationResult | null>(null);

  // Investigation State
  const [investigationContext, setInvestigationContext] = useState<InvestigationContext>(null);
  const [previousPage, setPreviousPage] = useState<PageId>('dashboard');

  const navigateTo = (page: PageId) => {
    if (page !== 'visualization') {
      setPreviousPage(page);
    }
    setActivePage(page);
    setIsMobileMenuOpen(false);
  };

  const handleVisualize = (context: InvestigationContext) => {
    setInvestigationContext(context);
    setActivePage('visualization');
  };

  // Chatbot interaction bridge state
  const [chatbotContext, setChatbotContext] = useState<Record<string, unknown> | null>(null);
  const [chatbotPrompt, setChatbotPrompt] = useState<string | null>(null);

  const fetchDashboardTelemetry = useCallback(async () => {
    setIsTelemetryLoading(true);
    try {
      const [overviewRes, riskRes, detectionsRes, eventsRes] = await Promise.all([
        api.get<OverviewMetrics>('/api/overview').catch(() => null),
        api.get<RiskData>('/api/risk').catch(() => null),
        api.get<DetectionItem[]>('/api/detections').catch(() => ({ data: [] })),
        api.get<SecurityEventItem[]>('/api/events?limit=50').catch(() => ({ data: [] })),
      ]);

      if (overviewRes) setOverviewMetrics(overviewRes.data);
      if (riskRes) setRiskData(riskRes.data);
      if (detectionsRes) setDetections(detectionsRes.data);
      if (eventsRes) setEvents(eventsRes.data);
    } catch (err) {
      console.error("Error fetching telemetry:", err);
    } finally {
      setIsTelemetryLoading(false);
    }
  }, []);

  useEffect(() => {
    // Health is fetched once by SystemHealthProvider; here we only load dashboard telemetry.
    fetchDashboardTelemetry();
  }, [fetchDashboardTelemetry]);

  const handleSimulationCompleted = (result: SimulationResult) => {
    setActiveSimulationId(result.simulation_id);
    setActiveScenarioName(result.scenario_name);
    setActiveSimulationResult(result);
    fetchDashboardTelemetry();
  };

  const handleAskChatbot = (telemetryContext: Record<string, unknown>, promptMessage: string) => {
    setChatbotContext(telemetryContext);
    setChatbotPrompt(promptMessage);
    setActivePage('copilot');
  };

  const apiUrl = API_DISPLAY_URL;

  const renderContent = () => {
    switch (activePage) {
      case 'dashboard':
        return (
          <DashboardPage
            overviewMetrics={overviewMetrics}
            riskData={riskData}
            detections={detections}
            isTelemetryLoading={isTelemetryLoading}
            onRefresh={fetchDashboardTelemetry}
            onInvestigateDetection={(id) => setSelectedDetectionId(id)}
          />
        );
      case 'phishing':
        return <PhishingDetectionPage onVisualize={handleVisualize} />;
      case 'intrusion':
        return (
          <IntrusionDetectionPage
            onSimulationCompleted={handleSimulationCompleted}
            onAskChatbot={handleAskChatbot}
            onVisualize={(context) => handleVisualize(context)}
          />
        );
      case 'simulation':
        return (
          <AttackSimulationPage
            activeSimulationResult={activeSimulationResult}
            activeSimulationId={activeSimulationId}
            activeScenarioName={activeScenarioName}
            onSimulationCompleted={handleSimulationCompleted}
            onAskChatbot={handleAskChatbot}
            onInvestigateDetection={(id) => {
              if (activeSimulationResult) {
                handleVisualize({
                  type: 'intrusion',
                  detectionId: id,
                  simulationResult: activeSimulationResult,
                  simulationId: activeSimulationId,
                  scenarioName: activeScenarioName
                });
              } else {
                setSelectedDetectionId(id);
              }
            }}
            onVisualizeReplay={(datasetId, evalRunId, metrics, detections) => {
              handleVisualize({
                type: 'replay',
                datasetId,
                evalRunId,
                metrics,
                detections
              });
            }}
          />
        );
      case 'studio':
        return <ScenarioStudioPage />;
      case 'visualization':
        return (
          <VisualizationInvestigationPage  
            context={investigationContext}
            onAskChatbot={handleAskChatbot}
            onOpenInvestigation={(id) => setSelectedDetectionId(id)}
            onVisualizeIncident={(id) => handleVisualize({ type: 'incident', incidentId: id })}
            onBack={() => setActivePage(previousPage)}
          />
        );
      case 'adaptive':
        return (
          <div className="w-full max-w-[1400px] mx-auto h-[600px]">
            <AdaptiveLearningMetrics />
          </div>
        );
      case 'copilot':
        return (
          <div className="w-full max-w-[1400px] mx-auto h-full min-h-[600px]">
            <SecurityAssistant
              externalContext={chatbotContext}
              externalPrompt={chatbotPrompt}
              onClearExternalContext={() => {
                setChatbotContext(null);
                setChatbotPrompt(null);
              }}
            />
          </div>
        );
      case 'logs':
        return (
          <div className="w-full max-w-[1400px] mx-auto">
            <RecentEventsTable
              events={events}
              isLoading={isTelemetryLoading}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onAskChatbot={handleAskChatbot}
              onRefresh={fetchDashboardTelemetry}
            />
          </div>
        );
      case 'settings':
        return (
          <div className="w-full max-w-[1400px] mx-auto">
            <SettingsPage />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex h-screen bg-app text-ink overflow-hidden selection:bg-accent selection:text-white">
      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={() => setIsMobileMenuOpen(false)} />
      )}

      {/* Sidebar - Desktop */}
      <Sidebar
        activePage={activePage}
        onNavigate={navigateTo}
        connectionState={health.status}
        responseTime={health.latency}
        onPing={health.refresh}
        apiUrl={apiUrl}
        mlStatus={health.ml.status}
        integrityStatus={health.integrity.status}
      />

      {/* Sidebar - Mobile Drawer */}
      <div className={`fixed inset-y-0 left-0 z-50 w-64 transform transition-transform duration-300 ease-in-out md:hidden ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <Sidebar
          activePage={activePage}
          onNavigate={navigateTo}
          connectionState={health.status}
          responseTime={health.latency}
          onPing={health.refresh}
          apiUrl={apiUrl}
          mlStatus={health.ml.status}
          integrityStatus={health.integrity.status}
        />
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Mobile Topbar */}
        <div className="md:hidden flex items-center justify-between p-4 border-b border-line bg-surface">
          <div className="flex items-center gap-2 text-ink font-bold text-lg">
            <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20 text-accent-soft">
              <Shield className="w-4 h-4" />
            </div>
            AOD-IPS
          </div>
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            aria-label={isMobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={isMobileMenuOpen}
            className="text-ink-muted hover:text-ink"
          >
            {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Scrollable Main */}
        <main className="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">
          {renderContent()}
        </main>
      </div>

      {/* Modals */}
      {selectedEvent && (
        <SecurityEventModal
          event={selectedEvent}
          detections={detections}
          onClose={() => setSelectedEvent(null)}
          onAskChatbot={handleAskChatbot}
          onInvestigateDetection={(id) => setSelectedDetectionId(id)}
        />
      )}

      {selectedDetectionId !== null && (
        <DetectionInvestigationModal
          detectionId={selectedDetectionId}
          onClose={() => setSelectedDetectionId(null)}
          onEventClick={(ev) => {
            setSelectedDetectionId(null);
            setSelectedEvent(ev);
          }}
          onAskChatbot={handleAskChatbot}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <SystemHealthProvider>
        <AppShell />
      </SystemHealthProvider>
    </ToastProvider>
  );
}
