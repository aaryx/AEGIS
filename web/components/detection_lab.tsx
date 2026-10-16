"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  Bot,
  CheckCircle2,
  Clock,
  Compass,
  CornerUpLeft,
  Cpu,
  Download,
  FileCode,
  FileText,
  Filter,
  History,
  Layers,
  Play,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  Zap,
} from "lucide-react";
import { api, csv, display, download, Page, Row, User } from "@/lib/api";
import { Badge, CopyButton, JsonView, State } from "./ui";

type ReplayMetrics = {
  execution_duration_ms: number;
  events_per_second: number;
  events_evaluated: number;
  candidate_matches_count: number;
  active_matches_count: number;
  match_rate_percentage: number;
  concordant_matches_count: number;
  new_candidate_detections_count: number;
  dropped_detections_count: number;
  noisy_rule_indicator: boolean;
  ground_truth?: {
    ground_truth_available: boolean;
    true_positives?: number;
    false_positives?: number;
    true_negatives?: number;
    false_negatives?: number;
    total_attack_test_cases?: number;
    total_control_test_cases?: number;
    precision?: number | null;
    recall?: number | null;
    f1_score?: number | null;
    note?: string;
  };
};

type ReplayResult = {
  job_id: string;
  rule_id: string;
  status: string;
  dry_run: boolean;
  candidate_version?: number;
  active_version?: number;
  events_evaluated: number;
  candidate_matches: string[];
  active_matches: string[];
  new_detections: string[];
  dropped_detections: string[];
  metrics: ReplayMetrics;
  errors: string[];
  started_at: string;
  completed_at: string;
};

type MitreCoverageData = {
  catalog_total: number;
  covered_total: number;
  overall_coverage_pct: number;
  covered_techniques: Record<string, { name: string; tactic: string; rules: string[] }>;
  tactics: {
    tactic: string;
    total_techniques: number;
    covered_techniques_count: number;
    coverage_pct: number;
    covered_technique_ids: string[];
    uncovered_technique_ids: string[];
  }[];
};

const SAMPLE_SIGMA_RULE = `title: Encoded PowerShell Command Execution
id: f48b81d7-6604-4a6c-a549-ffe7aeca13dc
status: test
description: Detects encoded PowerShell command execution indicative of obfuscated scripts
author: Detection Engineering Team
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-encodedcommand'
      - '-enc'
  filter:
    CommandLine|contains: 'benign-healthcheck'
  condition: selection and not filter
level: high`;

export function DetectionLab({
  user,
  onOpen,
}: {
  user: User;
  onOpen: (resource: string, row: Row) => void;
}) {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"inventory" | "replay" | "sigma" | "coverage">(
    "inventory"
  );
  const [selectedRuleId, setSelectedRuleId] = useState<string>("AUTH-001");
  const [searchFilter, setSearchFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Replay execution state
  const [replayDataset, setReplayDataset] = useState("all");
  const [replayMaxEvents, setReplayMaxEvents] = useState(5000);
  const [replayRunning, setReplayRunning] = useState(false);
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null);
  const [replayError, setReplayError] = useState("");
  const [inspectEventId, setInspectEventId] = useState<string | null>(null);

  // AI explanation state
  const [aiLoading, setAiLoading] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<Row | null>(null);

  // Sigma import state
  const [sigmaYaml, setSigmaYaml] = useState(SAMPLE_SIGMA_RULE);
  const [sigmaResult, setSigmaResult] = useState<Row | null>(null);
  const [sigmaError, setSigmaError] = useState("");
  const [sigmaBusy, setSigmaBusy] = useState(false);

  // Promotion / Rollback state
  const [promoMessage, setPromoMessage] = useState("");

  // Query rules inventory
  const rulesQuery = useQuery({
    queryKey: ["rules", searchFilter, severityFilter, statusFilter],
    queryFn: () =>
      api<Page>(
        `rules?q=${encodeURIComponent(searchFilter)}&severity=${severityFilter}&limit=100`
      ),
  });

  // Query active rule detail
  const ruleDetailQuery = useQuery({
    queryKey: ["rule-detail", selectedRuleId],
    queryFn: () => api<Row>(`rules/${selectedRuleId}`),
    enabled: Boolean(selectedRuleId),
  });

  // Query rule versions
  const versionsQuery = useQuery({
    queryKey: ["rule-versions", selectedRuleId],
    queryFn: () => api<Page>(`rules/${selectedRuleId}/versions?limit=50`),
    enabled: Boolean(selectedRuleId),
  });

  // Query MITRE ATT&CK coverage
  const coverageQuery = useQuery({
    queryKey: ["coverage-mitre"],
    queryFn: () => api<MitreCoverageData>("coverage/mitre"),
  });

  // Run Replay
  async function handleRunReplay() {
    setReplayRunning(true);
    setReplayError("");
    setAiExplanation(null);
    try {
      const res = await api<ReplayResult>(`rules/${selectedRuleId}/replay`, "POST", {
        rule_id: selectedRuleId,
        dataset_name: replayDataset,
        target_type: "DATASET",
        max_events: replayMaxEvents,
        dry_run: true,
      });
      setReplayResult(res);
      queryClient.invalidateQueries({ queryKey: ["rule-detail", selectedRuleId] });
    } catch (err) {
      setReplayError((err as Error).message);
    } finally {
      setReplayRunning(false);
    }
  }

  // Trigger AI explanation
  async function handleAiExplain(jobId: string) {
    setAiLoading(true);
    try {
      const res = await api<Row>(`replays/${jobId}/ai-explain`, "POST");
      setAiExplanation(res);
    } catch (err) {
      setAiExplanation({ error: (err as Error).message });
    } finally {
      setAiLoading(false);
    }
  }

  // Translate Sigma YAML
  async function handleSigmaTranslate() {
    setSigmaBusy(true);
    setSigmaError("");
    setSigmaResult(null);
    try {
      const res = await api<Row>("rules/import-sigma", "POST", { yaml_rule: sigmaYaml });
      setSigmaResult(res);
    } catch (err) {
      setSigmaError((err as Error).message);
    } finally {
      setSigmaBusy(false);
    }
  }

  // Save imported Sigma as draft
  async function handleSaveSigmaDraft() {
    if (!sigmaResult?.rule) return;
    setSigmaBusy(true);
    try {
      const doc = sigmaResult.rule as Row;
      await api(`rules/${doc.id}`, "PUT", {
        document: doc,
        summary: "Imported from Sigma rule definition",
        version: 0,
        enabled: false,
        lifecycle_stage: "DRAFT",
      });
      setPromoMessage(`Draft rule ${doc.id} created successfully.`);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      setSelectedRuleId(String(doc.id));
      setActiveTab("inventory");
    } catch (err) {
      setSigmaError((err as Error).message);
    } finally {
      setSigmaBusy(false);
    }
  }

  // Activate rule version
  async function handleActivateRule(version: number) {
    if (!confirm(`Are you sure you want to approve and activate version ${version} of ${selectedRuleId}?`)) {
      return;
    }
    try {
      await api(`rules/${selectedRuleId}/activate`, "POST", {
        version,
        summary: `Authorized production activation by ${user.username}`,
      });
      setPromoMessage(`Rule ${selectedRuleId} v${version} successfully activated in production.`);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      queryClient.invalidateQueries({ queryKey: ["rule-detail", selectedRuleId] });
      queryClient.invalidateQueries({ queryKey: ["rule-versions", selectedRuleId] });
    } catch (err) {
      alert(`Activation error: ${(err as Error).message}`);
    }
  }

  // Rollback rule version
  async function handleRollbackRule(targetVersion: number) {
    const reason = prompt(
      `Enter authorization justification to rollback ${selectedRuleId} to v${targetVersion}:`,
      "Reverting to known-good version"
    );
    if (!reason) return;

    try {
      await api(`rules/${selectedRuleId}/rollback`, "POST", {
        target_version: targetVersion,
        summary: reason,
      });
      setPromoMessage(`Rule ${selectedRuleId} rolled back to v${targetVersion}.`);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      queryClient.invalidateQueries({ queryKey: ["rule-detail", selectedRuleId] });
      queryClient.invalidateQueries({ queryKey: ["rule-versions", selectedRuleId] });
    } catch (err) {
      alert(`Rollback error: ${(err as Error).message}`);
    }
  }

  const rulesList = (rulesQuery.data?.items as Row[]) || [];
  const activeRule = ruleDetailQuery.data;
  const versionsList = (versionsQuery.data?.items as Row[]) || [];

  return (
    <div className="detection-lab-shell">
      {/* Overview Strip */}
      <div className="summary-strip">
        <span>
          <ShieldCheck size={16} /> Detection Engineering & Attack Replay Lab
        </span>
        <span>
          Sandbox dry-run evaluation · Isolated state · Controlled rule promotion
        </span>
      </div>

      {promoMessage && (
        <div className="toast-banner toast-success" role="status">
          <span>{promoMessage}</span>
          <button className="toast-close" onClick={() => setPromoMessage("")}>
            ✕
          </button>
        </div>
      )}

      {/* Main Tab Navigation */}
      <div className="detection-lab-tabs">
        <button
          className={activeTab === "inventory" ? "active" : ""}
          onClick={() => setActiveTab("inventory")}
        >
          <Layers size={15} /> Rule Inventory & Status
        </button>
        <button
          className={activeTab === "replay" ? "active" : ""}
          onClick={() => setActiveTab("replay")}
        >
          <Zap size={15} /> Attack Replay Lab
        </button>
        <button
          className={activeTab === "sigma" ? "active" : ""}
          onClick={() => setActiveTab("sigma")}
        >
          <Upload size={15} /> Sigma Importer
        </button>
        <button
          className={activeTab === "coverage" ? "active" : ""}
          onClick={() => setActiveTab("coverage")}
        >
          <Compass size={15} /> MITRE ATT&CK Matrix
        </button>
      </div>

      {/* TAB 1: RULE INVENTORY & LIFECYCLE */}
      {activeTab === "inventory" && (
        <div className="inventory-workspace">
          {/* Quick Stats Grid */}
          <section className="metric-grid" aria-label="Rule Stats">
            <article className="metric accent">
              <div>
                <span>Total Detection Rules</span>
                <Layers size={16} />
              </div>
              <strong>{rulesList.length}</strong>
              <p>Managed in organization</p>
            </article>
            <article className="metric green">
              <div>
                <span>Active Detections</span>
                <CheckCircle2 size={16} />
              </div>
              <strong>{rulesList.filter((r) => r.enabled !== false).length}</strong>
              <p>Live event evaluation</p>
            </article>
            <article className="metric amber">
              <div>
                <span>Draft / In-Review</span>
                <History size={16} />
              </div>
              <strong>{rulesList.filter((r) => r.lifecycle_stage === "DRAFT").length}</strong>
              <p>Candidate promotion stages</p>
            </article>
            <article className="metric purple">
              <div>
                <span>ATT&CK Catalog Coverage</span>
                <Compass size={16} />
              </div>
              <strong>{coverageQuery.data?.overall_coverage_pct || 0}%</strong>
              <p>{coverageQuery.data?.covered_total || 0} techniques mapped</p>
            </article>
          </section>

          {/* Filtering Toolbar */}
          <div className="toolbar">
            <label className="search-field">
              <Search size={16} />
              <input
                placeholder="Search rule ID, name, or description…"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All status</option>
              <option value="active">Active</option>
              <option value="draft">Draft</option>
              <option value="disabled">Disabled</option>
            </select>
            <button
              onClick={() =>
                download("aegis-detection-rules.csv", csv(rulesList), "text/csv")
              }
            >
              <Download size={15} /> Export Catalog
            </button>
            <button
              className="primary"
              onClick={() => setActiveTab("sigma")}
            >
              <Upload size={15} /> Import Sigma Rule
            </button>
          </div>

          {/* Rules Table & Inspection Split */}
          <div className="rules-layout">
            <section className="panel rules-table-panel">
              <State
                loading={rulesQuery.isPending}
                error={rulesQuery.error}
                empty={rulesList.length === 0}
              />
              {rulesList.length > 0 && (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Severity</th>
                        <th>Version</th>
                        <th>Stage</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rulesList.map((rule) => {
                        const doc = (rule.document as Row) || {};
                        const isSelected = rule.rule_id === selectedRuleId;
                        return (
                          <tr
                            key={String(rule.id)}
                            className={isSelected ? "selected-row" : ""}
                            onClick={() => setSelectedRuleId(String(rule.rule_id))}
                            style={{ cursor: "pointer" }}
                          >
                            <td>
                              <strong className="mono">{String(rule.rule_id)}</strong>
                            </td>
                            <td>{display(doc.name || rule.rule_id)}</td>
                            <td>
                              <Badge value={doc.severity || "medium"} />
                            </td>
                            <td>
                              <span className="mono">v{display(rule.version)}</span>
                            </td>
                            <td>
                              <span className="lifecycle-tag">
                                {display(rule.lifecycle_stage || "ACTIVE")}
                              </span>
                            </td>
                            <td>
                              <Badge
                                value={rule.enabled !== false ? "active" : "disabled"}
                              />
                            </td>
                            <td>
                              <div style={{ display: "flex", gap: "6px" }}>
                                <button
                                  className="text-button"
                                  aria-label={`Open ${display(doc.name || rule.rule_id || rule.id)}`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onOpen("rules", rule);
                                  }}
                                >
                                  Open ↗
                                </button>
                                <button
                                  className="text-button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedRuleId(String(rule.rule_id));
                                    setActiveTab("replay");
                                  }}
                                >
                                  Replay →
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {/* Selected Rule Inspector */}
            {activeRule && (
              <section className="panel rule-inspector-panel">
                <div className="panel-heading">
                  <h2>
                    <FileCode size={17} /> {String(activeRule.rule_id)}
                  </h2>
                  <div className="actions">
                    <button
                      className="text-button"
                      aria-label={`Open ${display((activeRule.document as Row)?.name || activeRule.rule_id || activeRule.id)}`}
                      onClick={() => onOpen("rules", activeRule)}
                    >
                      Open in Editor ↗
                    </button>
                    <button
                      className="primary"
                      onClick={() => setActiveTab("replay")}
                    >
                      <Play size={14} /> Replay Rule
                    </button>
                  </div>
                </div>

                <div className="rule-meta-box">
                  <div>
                    <span className="subtle">Active Version:</span>{" "}
                    <strong>v{display(activeRule.version)}</strong>
                  </div>
                  <div>
                    <span className="subtle">Lifecycle Stage:</span>{" "}
                    <span className="lifecycle-tag">
                      {display(activeRule.lifecycle_stage || "ACTIVE")}
                    </span>
                  </div>
                  <div>
                    <span className="subtle">Severity:</span>{" "}
                    <Badge value={(activeRule.document as Row)?.severity || "medium"} />
                  </div>
                  <div>
                    <span className="subtle">ATT&CK Mapping:</span>{" "}
                    <span className="mono">
                      {((activeRule.document as Row)?.mitre_techniques as string[])?.join(", ") || "None"}
                    </span>
                  </div>
                </div>

                <h3>Version Changelog & Promotion History</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Version</th>
                        <th>Summary</th>
                        <th>Author</th>
                        <th>Created</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {versionsList.map((ver) => (
                        <tr key={String(ver.id)}>
                          <td>
                            <strong>v{display(ver.version)}</strong>
                          </td>
                          <td>{display(ver.summary)}</td>
                          <td className="mono">{display(ver.author)}</td>
                          <td>{display(ver.created_at)}</td>
                          <td>
                            {Number(ver.version) !== Number(activeRule.version) && (
                              <button
                                className="text-button"
                                onClick={() => handleRollbackRule(Number(ver.version))}
                              >
                                Rollback ↺
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <h3>Rule Document Definition</h3>
                <JsonView value={activeRule.document} />
              </section>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: ATTACK REPLAY LAB */}
      {activeTab === "replay" && (
        <div className="replay-workspace">
          <section className="panel replay-config-panel">
            <div className="panel-heading">
              <h2>
                <Zap size={18} /> Replay Configuration & Execution
              </h2>
              <span className="subtle">
                Dry-run isolation · Zero production alert creation
              </span>
            </div>

            <div className="replay-form-grid">
              <div>
                <label>Target Detection Rule</label>
                <select
                  value={selectedRuleId}
                  onChange={(e) => setSelectedRuleId(e.target.value)}
                >
                  {rulesList.map((r) => (
                    <option key={String(r.id)} value={String(r.rule_id)}>
                      {String(r.rule_id)} — {display((r.document as Row)?.name || "")}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label>Labelled Historical Attack Dataset</label>
                <select
                  value={replayDataset}
                  onChange={(e) => setReplayDataset(e.target.value)}
                >
                  <option value="all">All Curated Labelled Fixtures (35 Scenarios)</option>
                  <option value="AUTH-001">AUTH-001: Repeated Auth Failures (Brute Force)</option>
                  <option value="AUTH-002">AUTH-002: Password Spraying Across Accounts</option>
                  <option value="PROC-001">PROC-001: Encoded PowerShell Command Execution</option>
                  <option value="NET-005">NET-005: Periodic C2 Network Beaconing</option>
                  <option value="WEB-001">WEB-001: Directory & Path Traversal Attack</option>
                  <option value="DATA-002">DATA-002: Critical System File Read (/etc/shadow)</option>
                </select>
              </div>

              <div>
                <label>Event Limit Boundary</label>
                <input
                  type="number"
                  min={100}
                  max={50000}
                  step={500}
                  value={replayMaxEvents}
                  onChange={(e) => setReplayMaxEvents(Number(e.target.value))}
                />
              </div>

              <div className="replay-button-box">
                <button
                  className="primary btn-large"
                  disabled={replayRunning}
                  onClick={handleRunReplay}
                >
                  {replayRunning ? (
                    <>
                      <span className="spinner" /> Replaying Telemetry…
                    </>
                  ) : (
                    <>
                      <Play size={16} /> Execute Historical Replay (Dry Run)
                    </>
                  )}
                </button>
              </div>
            </div>

            {replayError && <p className="error-text" role="alert">{replayError}</p>}
          </section>

          {/* Replay Results & Quality Scorecard */}
          {replayResult && (
            <div className="replay-results-container">
              {/* Noisy Rule Indicator Alert */}
              {replayResult.metrics.noisy_rule_indicator && (
                <div className="alert-banner warning">
                  <AlertTriangle size={20} />
                  <div>
                    <strong>Noisy Detection Rule Indicator Detected</strong>
                    <p>
                      This rule triggered on control/benign events or exhibited an
                      abnormally elevated match rate ({replayResult.metrics.match_rate_percentage}%).
                      Tuning predicates or tightening aggregation thresholds is recommended.
                    </p>
                  </div>
                </div>
              )}

              {/* Quality & Throughput Metrics Cards */}
              <section className="metric-grid">
                <article className="metric">
                  <div>
                    <span>Evaluated Events</span>
                    <Layers size={16} />
                  </div>
                  <strong>{replayResult.events_evaluated.toLocaleString()}</strong>
                  <p>In {replayResult.metrics.execution_duration_ms} ms</p>
                </article>
                <article className="metric accent">
                  <div>
                    <span>Replay Throughput</span>
                    <Zap size={16} />
                  </div>
                  <strong>{replayResult.metrics.events_per_second} EPS</strong>
                  <p>Sustained replay throughput</p>
                </article>
                <article className="metric green">
                  <div>
                    <span>Total Matches</span>
                    <ShieldAlert size={16} />
                  </div>
                  <strong>{replayResult.candidate_matches.length}</strong>
                  <p>{replayResult.metrics.match_rate_percentage}% match rate</p>
                </article>
                <article className="metric purple">
                  <div>
                    <span>Ground Truth Recall</span>
                    <ShieldCheck size={16} />
                  </div>
                  <strong>
                    {replayResult.metrics.ground_truth?.ground_truth_available
                      ? `${Math.round((replayResult.metrics.ground_truth.recall || 0) * 100)}%`
                      : "N/A"}
                  </strong>
                  <p>
                    {replayResult.metrics.ground_truth?.ground_truth_available
                      ? `Precision: ${Math.round((replayResult.metrics.ground_truth.precision || 0) * 100)}%`
                      : "Unlabelled dataset"}
                  </p>
                </article>
              </section>

              {/* Ground Truth Matrix (Only if verified ground truth exists!) */}
              {replayResult.metrics.ground_truth?.ground_truth_available && (
                <section className="panel ground-truth-panel">
                  <div className="panel-heading">
                    <h2>
                      <ShieldCheck size={17} /> Ground Truth Detection Quality Scorecard
                    </h2>
                    <span className="badge active">Verified Synthetic Ground Truth</span>
                  </div>

                  <div className="confusion-matrix-grid">
                    <div className="cm-cell tp">
                      <span className="cm-title">True Positives (TP)</span>
                      <strong>{replayResult.metrics.ground_truth.true_positives}</strong>
                      <p>Correctly detected attack events</p>
                    </div>
                    <div className="cm-cell fp">
                      <span className="cm-title">False Positives (FP)</span>
                      <strong>{replayResult.metrics.ground_truth.false_positives}</strong>
                      <p>Benign events erroneously flagged</p>
                    </div>
                    <div className="cm-cell fn">
                      <span className="cm-title">False Negatives (FN)</span>
                      <strong>{replayResult.metrics.ground_truth.false_negatives}</strong>
                      <p>Attack events missed by rule</p>
                    </div>
                    <div className="cm-cell tn">
                      <span className="cm-title">True Negatives (TN)</span>
                      <strong>{replayResult.metrics.ground_truth.true_negatives}</strong>
                      <p>Benign events correctly ignored</p>
                    </div>
                  </div>

                  <div className="f1-strip">
                    <span>
                      F1-Score:{" "}
                      <strong>
                        {replayResult.metrics.ground_truth.f1_score !== undefined
                          ? replayResult.metrics.ground_truth.f1_score
                          : "0.0"}
                      </strong>
                    </span>
                    <span>
                      Total Attack Test Cases:{" "}
                      <strong>
                        {replayResult.metrics.ground_truth.total_attack_test_cases}
                      </strong>
                    </span>
                    <span>
                      Total Control Cases:{" "}
                      <strong>
                        {replayResult.metrics.ground_truth.total_control_test_cases}
                      </strong>
                    </span>
                  </div>
                </section>
              )}

              {/* Version Comparison Delta */}
              <section className="panel comparison-delta-panel">
                <div className="panel-heading">
                  <h2>
                    <ArrowLeftRight size={17} /> Candidate vs. Active Version Delta
                  </h2>
                  <div className="toolbar">
                    <button
                      className="primary"
                      disabled={aiLoading}
                      onClick={() => handleAiExplain(replayResult.job_id)}
                    >
                      <Bot size={15} />{" "}
                      {aiLoading ? "Consulting AI…" : "Explain Matches with AI"}
                    </button>
                    {activeRule && (
                      <button
                        className="btn-success"
                        onClick={() =>
                          handleActivateRule(Number(activeRule.version))
                        }
                      >
                        <CheckCircle2 size={15} /> Approve & Activate Version
                      </button>
                    )}
                  </div>
                </div>

                <div className="delta-summary-bar">
                  <span className="delta-item concordant">
                    Concordant: <strong>{replayResult.metrics.concordant_matches_count}</strong>
                  </span>
                  <span className="delta-item new">
                    New Detections: <strong>{replayResult.new_detections.length}</strong>
                  </span>
                  <span className="delta-item dropped">
                    Dropped Detections: <strong>{replayResult.dropped_detections.length}</strong>
                  </span>
                </div>

                {/* AI Explanation Result Box */}
                {aiExplanation && (
                  <div className="ai-explanation-box">
                    <div className="ai-header">
                      <Sparkles size={16} />
                      <strong>AEGIS Detection Intelligence Explanation</strong>
                      <span className="subtle">Grounded in concrete event evidence</span>
                    </div>
                    {aiExplanation.error ? (
                      <p className="error-text">{String(aiExplanation.error)}</p>
                    ) : (
                      <JsonView value={aiExplanation.explanation} />
                    )}
                  </div>
                )}

                {/* Matched Events Table */}
                <h3>Matched Event Evidence</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Event Identifier</th>
                        <th>Candidate Match</th>
                        <th>Active Match</th>
                        <th>Inspection</th>
                      </tr>
                    </thead>
                    <tbody>
                      {replayResult.candidate_matches.slice(0, 50).map((eventId) => {
                        const isNew = replayResult.new_detections.includes(eventId);
                        return (
                          <tr key={eventId}>
                            <td>
                              <strong className="mono">{eventId}</strong>
                              {isNew && <span className="badge high" style={{ marginLeft: 8 }}>NEW</span>}
                            </td>
                            <td>
                              <span className="badge success">MATCH</span>
                            </td>
                            <td>
                              <span className="badge neutral">
                                {replayResult.active_matches.includes(eventId) ? "MATCH" : "MISSED"}
                              </span>
                            </td>
                            <td>
                              <button
                                className="text-button"
                                onClick={() => setInspectEventId(eventId)}
                              >
                                View Evidence ↗
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: SIGMA IMPORTER */}
      {activeTab === "sigma" && (
        <div className="sigma-workspace">
          <section className="panel">
            <div className="panel-heading">
              <h2>
                <Upload size={18} /> Import Sigma Detection Rule
              </h2>
              <span className="subtle">
                Deterministic translation · Strict operator validation · No silent reinterpretation
              </span>
            </div>

            <div className="sigma-layout">
              <div className="sigma-editor-col">
                <label>
                  Sigma Rule Document (YAML)
                  <textarea
                    className="code-editor"
                    rows={20}
                    value={sigmaYaml}
                    onChange={(e) => setSigmaYaml(e.target.value)}
                    spellCheck={false}
                  />
                </label>
                <div className="toolbar">
                  <button
                    className="primary"
                    disabled={sigmaBusy}
                    onClick={handleSigmaTranslate}
                  >
                    {sigmaBusy ? "Validating…" : "Validate & Translate Sigma"}
                  </button>
                </div>
                {sigmaError && (
                  <p className="error-text" role="alert">
                    {sigmaError}
                  </p>
                )}
              </div>

              <div className="sigma-preview-col">
                <h3>Translated AEGIS Detection Rule (JSON)</h3>
                {sigmaResult?.rule ? (
                  <>
                    <JsonView value={sigmaResult.rule} />
                    <div className="toolbar" style={{ marginTop: 12 }}>
                      <button
                        className="btn-success"
                        disabled={sigmaBusy}
                        onClick={handleSaveSigmaDraft}
                      >
                        <CheckCircle2 size={15} /> Save as Draft Rule in Catalog
                      </button>
                    </div>
                  </>
                ) : (
                  <p className="subtle">
                    Click &quot;Validate &amp; Translate Sigma&quot; to review the compiled AEGIS rule.
                  </p>
                )}
              </div>
            </div>
          </section>
        </div>
      )}

      {/* TAB 4: MITRE ATT&CK COVERAGE */}
      {activeTab === "coverage" && (
        <div className="coverage-workspace">
          <section className="panel">
            <div className="panel-heading">
              <h2>
                <Compass size={18} /> MITRE ATT&CK Enterprise Matrix Coverage
              </h2>
              <span className="subtle">
                Curated tactic and technique mapping across active detection rules
              </span>
            </div>

            <State
              loading={coverageQuery.isPending}
              error={coverageQuery.error}
            />

            {coverageQuery.data && (
              <>
                <div className="coverage-gauge-header">
                  <div className="gauge-number">
                    {coverageQuery.data.overall_coverage_pct}%
                  </div>
                  <div>
                    <strong>Overall Catalog Technique Coverage</strong>
                    <p>
                      {coverageQuery.data.covered_total} of {coverageQuery.data.catalog_total} curated
                      techniques covered by active detection rules.
                    </p>
                  </div>
                </div>

                <div className="tactics-grid">
                  {coverageQuery.data.tactics.map((tac) => (
                    <article key={tac.tactic} className="tactic-card">
                      <div className="tactic-header">
                        <strong>{tac.tactic.toUpperCase().replaceAll("-", " ")}</strong>
                        <span className="mono">{tac.coverage_pct}%</span>
                      </div>
                      <progress
                        value={tac.covered_techniques_count}
                        max={Math.max(1, tac.total_techniques)}
                      />
                      <div className="tactic-details">
                        <span>
                          {tac.covered_techniques_count} / {tac.total_techniques} covered
                        </span>
                      </div>
                      <div className="technique-tags">
                        {tac.covered_technique_ids.map((id) => (
                          <span key={id} className="badge success" title={id}>
                            {id}
                          </span>
                        ))}
                        {tac.uncovered_technique_ids.map((id) => (
                          <span key={id} className="badge neutral" title={`Uncovered: ${id}`}>
                            {id}
                          </span>
                        ))}
                      </div>
                    </article>
                  ))}
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
