import { aegisAI } from "./ai.functions";
import type {
  AICodeAnalysisResult,
  AIExploitabilityResult,
  AIAttackPathsResult,
  AISupplyChainResult,
  AIBinaryResult,
  AIThreatIntelResult,
  AIRemediationResult,
  AIVerificationResult,
  AIDriftResult,
  AIInvestigationResult,
} from "./types";

async function callAI<T>(payload: {
  action: string;
  userContent?: string;
  messages?: { role: "user" | "assistant"; content: string }[];
}): Promise<T> {
  const data = await aegisAI({ data: payload });
  if (!data?.ok) {
    throw new Error("AI request returned an error response.");
  }
  return data.result as T;
}

/**
 * The model is instructed to always return a summary block, but a truncated or
 * partial response must not crash the results view — rebuild it from findings.
 */
function normalizeAnalysis(
  result: AICodeAnalysisResult,
  code: string,
  language?: string,
): AICodeAnalysisResult {
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const count = (severity: string) => findings.filter((f) => f.severity === severity).length;
  const fallback = {
    total: findings.length,
    critical: count("critical"),
    high: count("high"),
    medium: count("medium"),
    low: count("low"),
    info: count("info"),
    language: language || "auto-detect",
    loc: code.split("\n").length,
  };
  const summary = { ...fallback, ...(result?.summary ?? {}) };
  return { ...result, findings, summary } as AICodeAnalysisResult;
}

export const ai = {
  analyzeCode: async (code: string, language?: string) => {
    const result = await callAI<AICodeAnalysisResult>({
      action: "analyze_code",
      userContent: `Language: ${language || "auto-detect"}\n\nAnalyze the following code for security vulnerabilities:\n\n\`\`\`\n${code}\n\`\`\``,
    });
    return normalizeAnalysis(result, code, language);
  },

  assessExploitability: (finding: Record<string, unknown>, appContext: string) =>
    callAI<AIExploitabilityResult>({
      action: "exploitability",
      userContent: `Vulnerability finding:\n${JSON.stringify(finding, null, 2)}\n\nApplication context:\n${appContext}`,
    }),

  generateAttackPaths: (findings: Record<string, unknown>[], appContext: string) =>
    callAI<AIAttackPathsResult>({
      action: "attack_paths",
      userContent: `Findings:\n${JSON.stringify(findings, null, 2)}\n\nApplication context:\n${appContext}`,
    }),

  analyzeSupplyChain: (manifest: string, appContext: string) =>
    callAI<AISupplyChainResult>({
      action: "supply_chain",
      userContent: `Dependency manifest / SBOM input:\n${manifest}\n\nApplication context:\n${appContext}`,
    }),

  reverseEngineer: (binaryMetadata: string) =>
    callAI<AIBinaryResult>({
      action: "reverse_engineering",
      userContent: `Binary metadata (strings, imports, functions, behavior):\n${binaryMetadata}`,
    }),

  fuseThreatIntel: (cves: string[], context: string) =>
    callAI<AIThreatIntelResult>({
      action: "threat_intel",
      userContent: `CVEs to correlate: ${cves.join(", ") || "none provided"}\n\nContext:\n${context}`,
    }),

  remediate: (finding: Record<string, unknown>, code: string) =>
    callAI<AIRemediationResult>({
      action: "remediate",
      userContent: `Vulnerability:\n${JSON.stringify(finding, null, 2)}\n\nOriginal code:\n\`\`\`\n${code}\n\`\`\``,
    }),

  verifyRemediation: (finding: Record<string, unknown>, fixedCode: string) =>
    callAI<AIVerificationResult>({
      action: "verify_remediation",
      userContent: `Original vulnerability:\n${JSON.stringify(finding, null, 2)}\n\nRemediated code:\n\`\`\`\n${fixedCode}\n\`\`\``,
    }),

  detectDrift: (before: string, after: string) =>
    callAI<AIDriftResult>({
      action: "drift",
      userContent: `BEFORE state:\n${before}\n\nAFTER state:\n${after}`,
    }),

  investigate: (context: string) =>
    callAI<AIInvestigationResult>({
      action: "investigate",
      userContent: context,
    }),

  chat: (messages: { role: "user" | "assistant"; content: string }[]) =>
    callAI<string>({
      action: "chat",
      messages,
    }),
};
