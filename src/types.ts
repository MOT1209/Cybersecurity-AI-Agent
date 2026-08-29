export type AgentType =
  | 'recon'
  | 'web_security'
  | 'vuln_analysis'
  | 'code_security'
  | 'network_security'
  | 'cloud_security'
  | 'container_security'
  | 'digital_forensics'
  | 'threat_intel'
  | 'remediation'
  | 'reporting'
  | 'testing';

export interface AgentMetadata {
  id: AgentType;
  nameEn: string;
  nameAr: string;
  roleDescriptionEn: string;
  roleDescriptionAr: string;
  icon: string;
  badgeColor: string;
  tools: string[];
  capabilities: string[];
  systemPrompt: string;
}

export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ToolPlugin {
  id: string;
  name: string;
  category: 'Recon' | 'Web' | 'Code' | 'Network' | 'Cloud' | 'Container' | 'Forensics' | 'Intel' | 'Testing';
  descriptionAr: string;
  descriptionEn: string;
  version: string;
  riskLevel: RiskLevel;
  requiresHumanApproval: boolean;
  requiredPermissions: string[];
  timeoutSeconds: number;
  inputSchema: {
    targetType: 'ip' | 'domain' | 'url' | 'code' | 'pcap' | 'container' | 'config' | 'log';
    sampleInput: string;
    params: { name: string; type: string; defaultVal: string; description: string }[];
  };
}

export interface SecurityPolicy {
  allowedTargets: string[];
  deniedTargets: string[];
  maxScanConcurrency: number;
  requireApprovalForHighRisk: boolean;
  strictSandboxEnforced: boolean;
  auditLoggingEnabled: boolean;
}

export interface ProjectScope {
  id: string;
  name: string;
  targetDomain: string;
  targetIps: string[];
  environmentType: 'Production Lab' | 'CTF Arena' | 'Staging Environment' | 'Local Sandbox';
  authorizationGrantedBy: string;
  authorizationDate: string;
  validUntil: string;
  inScope: string[];
  outOfScope: string[];
  policy: SecurityPolicy;
}

export interface FindingValidation {
  isValidated: boolean;
  validatedByAgent: AgentType;
  confidenceScore: number; // 0 - 100
  evidenceTrace: string[];
  falsePositiveAnalysis: string;
  retestStatus: 'UNTESTED' | 'CONFIRMED' | 'FIXED' | 'RECURRED';
}

export interface SecurityFinding {
  id: string;
  projectId: string;
  title: string;
  target: string;
  timestamp: string;
  discoveredByAgent: AgentType;
  toolUsed: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvssScore: number;
  cwe: string;
  owaspCategory?: string;
  description: string;
  impact: string;
  evidence: string;
  validation: FindingValidation;
  remediation: {
    summary: string;
    codeFix?: string;
    configPatch?: string;
    hardeningSteps: string[];
    verificationCommand?: string;
  };
}

export interface OrchestrationStep {
  id: string;
  stepNumber: number;
  phase: 'UNDERSTAND' | 'ANALYZE' | 'PLAN' | 'AUTHORIZE' | 'EXECUTE' | 'OBSERVE' | 'VALIDATE' | 'REMEDIATION' | 'RETEST' | 'REPORT';
  agent: AgentType | 'orchestrator' | 'gateway';
  toolName?: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'GATEWAY_BLOCKED' | 'FAILED';
  inputSummary: string;
  outputSummary: string;
  detailedLog: string;
  timestamp: string;
  durationMs: number;
}

export interface OrchestrationPlan {
  id: string;
  traceId: string;
  userPrompt: string;
  projectId: string;
  target: string;
  createdAt: string;
  status: 'PLANNING' | 'AWAITING_APPROVAL' | 'EXECUTING' | 'COMPLETED' | 'HALTED';
  summaryAr: string;
  summaryEn: string;
  participatingAgents: AgentType[];
  steps: OrchestrationStep[];
  liveLogs: {
    id: string;
    timestamp: string;
    emitter: string;
    badge: string;
    message: string;
    type: 'info' | 'auth' | 'tool' | 'finding' | 'alert' | 'success';
  }[];
  generatedFindings: SecurityFinding[];
}

export interface GatewayCheckResult {
  isAllowed: boolean;
  target: string;
  scopeValidation: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNSPECIFIED';
  toolRisk: RiskLevel;
  humanApprovalRequired: boolean;
  reason: string;
  auditLogId: string;
}

export interface LabEnvironment {
  id: string;
  name: string;
  category: 'Vulnerable App' | 'API Gateway' | 'Container Escapes' | 'Active Directory Lab' | 'Network Defense';
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced' | 'Expert';
  targetIp: string;
  exposedPorts: number[];
  flag: string;
  description: string;
  dockerComposeHint: string;
  status: 'STOPPED' | 'STARTING' | 'RUNNING' | 'ISOLATED';
}

export interface KnowledgeItem {
  id: string;
  title: string;
  category: 'OWASP' | 'MITRE' | 'CWE' | 'CVE' | 'HARDENING' | 'TOOL_GUIDE';
  identifier: string;
  summary: string;
  details: string;
  tags: string[];
  remediationSnippet?: string;
}

export interface AuditLogEntry {
  id: string;
  traceId: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  status: 'ALLOWED' | 'DENIED' | 'FLAGGED' | 'COMPLETED';
  details: string;
  ipAddress: string;
}

// Retain compatibility with existing components
export type AgentPersona = 'tutor' | 'auditor' | 'pentest_coach' | 'soc_analyst' | 'cve_intel';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  persona?: AgentPersona;
  contextData?: any;
}

export interface VulnerabilityItem {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cwe?: string;
  owasp?: string;
  lines?: string;
  description: string;
  impact: string;
  remediation: string;
}

export interface AuditResult {
  summary: string;
  overallRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
  cvssScore: number;
  vulnerabilities: VulnerabilityItem[];
  securedCode: string;
  bestPractices: string[];
}

export interface TerminalEntry {
  id: string;
  command: string;
  output: string;
  explanation?: string;
  findings?: string[];
  suggestedNextCommands?: string[];
  timestamp: string;
  isError?: boolean;
}

export interface OWASPItem {
  id: string;
  code: string;
  titleAr: string;
  titleEn: string;
  descriptionAr: string;
  descriptionEn: string;
  cweList: string[];
  impact: string;
  prevention: string;
  exampleVulnerable: string;
  exampleFixed: string;
}

export interface MitreTactic {
  id: string;
  nameAr: string;
  nameEn: string;
  descriptionAr: string;
  descriptionEn: string;
  techniques: {
    id: string;
    name: string;
    description: string;
    detection: string;
  }[];
}

export interface CTFScenario {
  id: string;
  titleAr: string;
  titleEn: string;
  category: 'Web' | 'Network' | 'Crypto' | 'Linux/PrivEsc' | 'Forensics';
  difficulty: 'Easy' | 'Medium' | 'Hard';
  descriptionAr: string;
  descriptionEn: string;
  scenarioDetails: string;
  hints: string[];
  flag: string;
  solutionExplanation: string;
}

export interface SecurityReportFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  affectedAsset: string;
  description: string;
  remediation: string;
}

// Error Recovery & Safe Retry System Types
export type ErrorClassification =
  | 'TRANSIENT_TIMEOUT'
  | 'RATE_LIMITED'
  | 'PORT_UNREACHABLE'
  | 'WAF_BLOCKED'
  | 'SANDBOX_RESOURCE_EXHAUSTED'
  | 'SYNTAX_OR_SCHEMA_ERROR'
  | 'AUTH_FORBIDDEN';

export type RecoveryStrategyType =
  | 'EXPONENTIAL_BACKOFF'
  | 'FALLBACK_TOOL'
  | 'PROTOCOL_SWITCH'
  | 'THROTTLE_AND_RETRY'
  | 'PARAM_RESTRUCTURING'
  | 'ESCALATE_HUMAN';

export interface ErrorRecoveryEvent {
  id: string;
  timestamp: string;
  toolName: string;
  agentId: AgentType | string;
  target: string;
  rawError: string;
  rootCauseAr: string;
  rootCauseEn: string;
  classification: ErrorClassification;
  circuitBreakerState: 'CLOSED' | 'HALF_OPEN' | 'OPEN';
  retryCount: number;
  maxRetries: number;
  backoffDelayMs: number;
  strategy: RecoveryStrategyType;
  proposedFixAr: string;
  proposedFixEn: string;
  alternativeTool?: string;
  status: 'DETECTED' | 'RETRYING' | 'AUTO_RECOVERED' | 'FALLBACK_SUCCESS' | 'FAILED' | 'ESCALATED';
  executionLog: string[];
}
