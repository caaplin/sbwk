// Investigation orchestrator. Dependencies are injected for testability.
import { config as defaultConfig, investigateServices as defaultServices } from "./config.mjs";
import { deriveDependencyFindings, hasUnreachableDependency } from "./reason.mjs";

const log = (level, event, fields = {}) =>
  console.log(JSON.stringify({ level, event, service: "agent-core", timestamp: new Date().toISOString(), ...fields }));

/** Read-only client for the Agent Connector. Outages become error results, never throws. */
export function makeConnectorClient(cfg = defaultConfig) {
  return async function investigateDependencies(services) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), cfg.REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(new URL("/connector/investigate", cfg.CONNECTOR_URL), {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.CONNECTOR_API_TOKEN}` },
        body: JSON.stringify({ services }),
        signal: controller.signal
      });
      if (!res.ok) return { results: [], error: `Connector returned HTTP ${res.status}` };
      const data = await res.json();
      return { results: Array.isArray(data.results) ? data.results : [], summary: data.summary };
    } catch (e) {
      return { results: [], error: e.message || "Connector unreachable" };
    } finally {
      clearTimeout(timeout);
    }
  };
}

export function createInvestigator(deps) {
  const { store, investigateDependencies, inspectCodebase, reason, notifyEngineer, config, services = defaultServices } = deps;

  function decideEscalation(incident, result, findings, connectorError, recurring) {
    const reasons = [];
    if (result.confidence < config.ESCALATION_CONFIDENCE_THRESHOLD) reasons.push(`low confidence (${(result.confidence * 100).toFixed(0)}%)`);
    if (result.severity === "critical") reasons.push("critical severity");
    if (connectorError) reasons.push("connector unreachable");
    if (hasUnreachableDependency(findings)) reasons.push("a dependency is unreachable");
    if (incident.category === "upstream_unreachable" || incident.category === "timeout") reasons.push("application server unreachable");
    if (recurring >= 3) reasons.push(`recurring failure (${recurring + 1}x on this path)`);
    return { escalate: reasons.length > 0, escalationReason: reasons.join("; ") || undefined };
  }

  async function process(record) {
    const incident = record.incident;
    const recurring = store.recurrenceForPath(incident.path, incident.id);
    log("info", "investigation_started", { incidentId: incident.id, path: incident.path, recurring });

    const [dependency, codeFindings] = await Promise.all([investigateDependencies(services), inspectCodebase(incident)]);
    const recentCommits = config.codebase?.commits || [];
    const repoUrl = config.codebase?.repoUrl;
    const result = await reason({ incident, dependency, codeFindings, recurring, recentCommits, repoUrl });
    const dependencyFindings = deriveDependencyFindings(dependency);
    const { escalate, escalationReason } = decideEscalation(incident, result, dependencyFindings, dependency.error, recurring);

    const analysis = {
      incidentId: incident.id,
      mode: result.mode,
      ...(result.degradedFromLive ? { degradedFromLive: true, fallbackReason: result.fallbackReason } : {}),
      severity: result.severity,
      summary: result.summary,
      rootCause: result.rootCause,
      suggestedFixes: result.suggestedFixes,
      dependencyFindings,
      codeFindings,
      confidence: result.confidence,
      escalate,
      escalationReason,
      reasoning: result.reasoning,
      evidenceGraph: result.evidenceGraph,
      recurring,
      recentCommits,
      repoUrl,
      policy: { dryRun: config.DRY_RUN, autoRollback: config.AUTO_ROLLBACK, escalationThreshold: config.ESCALATION_CONFIDENCE_THRESHOLD },
      monitoringActive: config.MONITORING_ACTIVE,
      createdAt: new Date().toISOString()
    };
    store.attachAnalysis(incident.id, analysis);
    log("info", "incident_analyzed", {
      incidentId: incident.id, mode: analysis.mode,
      ...(analysis.degradedFromLive ? { degradedFromLive: true, fallbackReason: analysis.fallbackReason } : {}),
      severity: analysis.severity, confidence: analysis.confidence, escalate
    });

    if (escalate) {
      const notification = await notifyEngineer(incident, analysis, escalationReason || "escalation policy");
      store.setNotification(incident.id, notification);
    }
    return store.get(incident.id);
  }

  function startInvestigation(incident) {
    const record = store.create(incident);
    const completion = process(record).catch(e => {
      log("error", "investigation_failed", { incidentId: incident.id, error: e.message });
      return store.get(incident.id);
    });
    return { record, completion };
  }

  return { startInvestigation, runInvestigation: incident => startInvestigation(incident).completion };
}
