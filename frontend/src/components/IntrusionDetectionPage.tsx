import React from 'react';
import { SimulationResult } from './AttackSimulation';
import { InvestigationContext } from './VisualizationInvestigationPage';
import { IntrusionDetectionWorkspace } from './ids/IntrusionDetectionWorkspace';

interface IntrusionDetectionPageProps {
  // Retained for App.tsx compatibility. The expanded IDS module is self-contained
  // and produces its own analysis results rather than the legacy SimulationResult.
  onSimulationCompleted: (result: SimulationResult) => void;
  onAskChatbot?: (telemetryContext: Record<string, unknown>, promptMessage: string) => void;
  onVisualize: (context: InvestigationContext) => void;
}

export const IntrusionDetectionPage: React.FC<IntrusionDetectionPageProps> = ({ onAskChatbot }) => {
  return <IntrusionDetectionWorkspace onAskChatbot={onAskChatbot} />;
};
