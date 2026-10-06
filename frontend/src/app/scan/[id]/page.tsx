"use client";

import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams } from "next/navigation";
import { 
  ShieldCheck, 
  AlertTriangle, 
  BookOpen, 
  Search, 
  Code, 
  Globe, 
  Bug, 
  Cpu, 
  KeyRound, 
  Layers,
  ArrowLeft,
  RefreshCw,
  Sparkles,
  Check,
  Copy,
  Wand2,
  Download,
  FileText,
  X,
  CheckCircle2,
  ExternalLink
} from "lucide-react";

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [activeCategory, setActiveCategory] = useState<string>("ALL");
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Remediation & Report States
  const [fixingSingle, setFixingSingle] = useState(false);
  const [batchFixing, setBatchFixing] = useState(false);
  const [currentFix, setCurrentFix] = useState<any>(null);
  const [copied, setCopied] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportMarkdown, setReportMarkdown] = useState<string>("");
  const [loadingReport, setLoadingReport] = useState(false);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const loadData = async () => {
    try {
      setFetchError(null);
      const [scanRes, findingsRes] = await Promise.all([
        axios.get(`${API_URL}/api/scans/${id}`),
        axios.get(`${API_URL}/api/scans/${id}/findings`),
      ]);
      setScan(scanRes.data);
      setFindings(findingsRes.data);
      if (findingsRes.data.length > 0 && !selectedFinding) {
        setSelectedFinding(findingsRes.data[0]);
        setCurrentFix(findingsRes.data[0].ai_fix || null);
      }
    } catch (e: any) {
      if (e.response?.status === 404) {
        setFetchError("Scan record not found in the current database.");
      } else {
        setFetchError("Unable to connect to the backend server on port 8000.");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      if (scan && scan.status !== "COMPLETED" && scan.status !== "FAILED") {
        loadData();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  const selectFinding = (item: any) => {
    setSelectedFinding(item);
    setCurrentFix(item.ai_fix && item.ai_fix.fixed_code ? item.ai_fix : null);
    setCopied(false);
  };

  // Single Item Auto-Fix
  const handleSingleAutoFix = async () => {
    if (!selectedFinding) return;
    setFixingSingle(true);
    try {
      const res = await axios.post(`${API_URL}/api/findings/${selectedFinding.id}/autofix`);
      setCurrentFix(res.data.fix);
      selectedFinding.ai_fix = res.data.fix;
    } catch (err) {
      alert("Failed to generate AI patch. Make sure the backend is running.");
    } finally {
      setFixingSingle(false);
    }
  };

  // Batch Auto-Fix All Findings
  const handleBatchFixAll = async () => {
    setBatchFixing(true);
    try {
      await axios.post(`${API_URL}/api/scans/${id}/remediate-all`);
      await loadData();
      alert("Success: All detected vulnerabilities have been secured with AI!");
    } catch (err) {
      alert("Batch remediation failed. Please check backend connection.");
    } finally {
      setBatchFixing(false);
    }
  };

  // View Report Online Modal
  const openReportModal = async () => {
    setLoadingReport(true);
    setReportModalOpen(true);
    try {
      const res = await axios.get(`${API_URL}/api/scans/${id}/report`);
      setReportMarkdown(res.data.report_markdown);
    } catch (err) {
      setReportMarkdown("Failed to load audit report.");
    } finally {
      setLoadingReport(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredFindings = findings.filter((f) => {
    if (activeCategory === "ALL") return true;
    return f.category === activeCategory;
  });

  const counts = {
    ALL: findings.length,
    WEB: findings.filter((f) => f.category === "WEB").length,
    MALWARE: findings.filter((f) => f.category === "MALWARE").length,
    SYSTEM: findings.filter((f) => f.category === "SYSTEM").length,
    SECRET: findings.filter((f) => f.category === "SECRET").length,
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4 font-mono text-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-gray-400 text-sm">Loading PEGASUS Intelligence Scan...</p>
      </div>
    );
  }

  if (!scan || fetchError) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-5 text-center">
        <div className="w-14 h-14 rounded-2xl bg-red-950/40 border border-red-800 flex items-center justify-center text-red-400 shadow-xl">
          <AlertTriangle className="w-7 h-7" />
        </div>
        <div className="space-y-1.5">
          <h2 className="text-xl font-bold text-white">Scan Record Not Found</h2>
          <p className="text-sm text-gray-400 max-w-md">{fetchError}</p>
        </div>
        <div className="flex items-center gap-3 pt-2">
          <a
            href="/"
            className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-blue-600/20"
          >
            <ArrowLeft className="w-4 h-4" /> Return to Main Dashboard
          </a>
          <button
            onClick={() => { setLoading(true); loadData(); }}
            className="inline-flex items-center gap-2 bg-[#111827] text-gray-300 text-xs font-semibold px-4 py-2.5 rounded-xl border border-gray-800"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <a href="/" className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-400 hover:text-blue-400 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to All Projects
        </a>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* 1. Batch Fix with AI */}
          <button
            onClick={handleBatchFixAll}
            disabled={batchFixing || findings.length === 0}
            className="bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold text-xs px-3.5 py-2 rounded-xl transition-all shadow-lg shadow-purple-600/20 flex items-center gap-1.5 disabled:opacity-50"
          >
            {batchFixing ? (
              <>
                <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Auto-Securing Project...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
                <span>⚡ Auto-Fix All with AI</span>
              </>
            )}
          </button>

          {/* 2. Download Fixed Zip */}
          <a
            href={`${API_URL}/api/scans/${id}/download-fixed-code`}
            download
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs px-3.5 py-2 rounded-xl transition-all shadow-lg shadow-emerald-600/20 flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Fixed Code (.zip)</span>
          </a>

          {/* 3. Read Report Online */}
          <button
            onClick={openReportModal}
            className="bg-[#111827] hover:bg-gray-800 text-gray-300 border border-gray-700 font-semibold text-xs px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5 text-blue-400" />
            <span>View Remediation Report</span>
          </button>

          {/* 4. Download Report File */}
          <a
            href={`${API_URL}/api/scans/${id}/download-report`}
            download
            className="bg-[#111827] hover:bg-gray-800 text-gray-300 border border-gray-700 font-semibold text-xs px-3 py-2 rounded-xl transition-all flex items-center gap-1.5"
            title="Download Report as Markdown"
          >
            <Download className="w-3.5 h-3.5 text-gray-400" />
            <span>.md Report</span>
          </a>
        </div>
      </div>

      {/* Top Banner: Score, Grade, Debt */}
      <div className="bg-[#111827] border border-gray-800 rounded-2xl p-6 grid grid-cols-1 md:grid-cols-4 gap-6 shadow-lg">
        <div>
          <span className="text-xs uppercase tracking-wider text-gray-400 font-medium">Security Posture</span>
          <div className="text-4xl font-black mt-1 text-white">{scan.risk_score} <span className="text-sm font-normal text-gray-400">/ 100</span></div>
          <p className="text-xs text-gray-500 mt-1">Status: <span className="text-blue-400 uppercase font-mono font-semibold">{scan.status}</span></p>
        </div>
        <div>
          <span className="text-xs uppercase tracking-wider text-gray-400 font-medium">Platform Grade</span>
          <div className="text-4xl font-black mt-1 text-blue-400">Grade {scan.grade}</div>
          <p className="text-xs text-gray-500 mt-1">Based on aggregated threat scoring</p>
        </div>
        <div>
          <span className="text-xs uppercase tracking-wider text-gray-400 font-medium">Remediation Debt</span>
          <div className="text-3xl font-bold mt-1 text-white">{scan.summary?.estimated_remediation_hours || 0} hrs</div>
          <p className="text-xs text-gray-500 mt-1">Estimated engineering patch time</p>
        </div>
        <div>
          <span className="text-xs uppercase tracking-wider text-gray-400 font-medium">Severity Distribution</span>
          <div className="flex gap-2 mt-2 font-mono">
            <span className="bg-red-950/80 border border-red-800 text-red-300 text-xs px-2.5 py-1 rounded-lg">Crit: {scan.summary?.breakdown?.CRITICAL || 0}</span>
            <span className="bg-orange-950/80 border border-orange-800 text-orange-300 text-xs px-2.5 py-1 rounded-lg">High: {scan.summary?.breakdown?.HIGH || 0}</span>
            <span className="bg-yellow-950/80 border border-yellow-800 text-yellow-300 text-xs px-2.5 py-1 rounded-lg">Med: {scan.summary?.breakdown?.MEDIUM || 0}</span>
          </div>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex flex-wrap gap-2.5 border-b border-gray-800 pb-4">
        {[
          { key: "ALL", label: `All Findings (${counts.ALL})`, icon: Layers },
          { key: "WEB", label: `Web Vulnerabilities (${counts.WEB})`, icon: Globe },
          { key: "MALWARE", label: `Malware & Backdoors (${counts.MALWARE})`, icon: Bug },
          { key: "SYSTEM", label: `System Flaws (${counts.SYSTEM})`, icon: Cpu },
          { key: "SECRET", label: `Leaked Secrets (${counts.SECRET})`, icon: KeyRound },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeCategory === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => {
                setActiveCategory(tab.key);
                const first = findings.find((f) => tab.key === "ALL" || f.category === tab.key);
                if (first) selectFinding(first);
              }}
              className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                isActive 
                  ? "bg-blue-600 text-white shadow-lg shadow-blue-600/30 ring-1 ring-blue-400" 
                  : "bg-[#111827] text-gray-400 hover:text-white border border-gray-800"
              }`}
            >
              <Icon className="w-4 h-4" /> {tab.label}
            </button>
          );
        })}
      </div>

      {/* Main Analysis View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Finding Selector */}
        <div className="lg:col-span-5 bg-[#111827] border border-gray-800 rounded-2xl overflow-hidden shadow-lg">
          <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-[#131d33]/40">
            <h3 className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
              <Search className="w-4 h-4 text-blue-400" /> Showing {filteredFindings.length} Items
            </h3>
          </div>
          <div className="divide-y divide-gray-800 max-h-[680px] overflow-y-auto">
            {filteredFindings.length === 0 ? (
              <div className="p-10 text-center text-sm text-gray-500">
                No vulnerabilities in <span className="font-semibold text-gray-300">{activeCategory}</span>.
              </div>
            ) : (
              filteredFindings.map((item) => (
                <div
                  key={item.id}
                  onClick={() => selectFinding(item)}
                  className={`p-4 cursor-pointer transition-colors ${
                    selectedFinding?.id === item.id 
                      ? "bg-blue-950/50 border-l-4 border-blue-500" 
                      : "hover:bg-gray-800/40"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className={`text-[10px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider border ${
                      item.severity === "CRITICAL" ? "bg-red-950/80 text-red-300 border-red-800" :
                      item.severity === "HIGH" ? "bg-orange-950/80 text-orange-300 border-orange-800" :
                      "bg-yellow-950/80 text-yellow-300 border-yellow-800"
                    }`}>
                      {item.severity}
                    </span>

                    <div className="flex items-center gap-1.5">
                      {item.ai_fix?.fixed_code && (
                        <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 px-1.5 py-0.5 rounded font-mono flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5" /> Patched
                        </span>
                      )}
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded uppercase border bg-[#0B0F19] text-gray-400 border-gray-800">
                        {item.category}
                      </span>
                    </div>
                  </div>
                  <div className="text-sm font-semibold text-gray-200 line-clamp-1">{item.message}</div>
                  <div className="text-xs text-gray-400 mt-1 font-mono line-clamp-1">
                    {item.file_path}:{item.line_number}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Code Snippet & AI Remediation Studio */}
        <div className="lg:col-span-7 space-y-6">
          {selectedFinding ? (
            <>
              {/* Finding Action Header */}
              <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-lg flex flex-col sm:flex-row justify-between sm:items-center gap-4">
                <div>
                  <span className="text-xs font-mono text-gray-300 flex items-center gap-1.5">
                    <Code className="w-4 h-4 text-blue-400" />
                    {selectedFinding.file_path} (Line {selectedFinding.line_number})
                  </span>
                  <span className="inline-block mt-1 text-xs font-mono bg-[#0B0F19] text-blue-400 border border-blue-900/50 px-2.5 py-0.5 rounded-lg">
                    {selectedFinding.cwe}
                  </span>
                </div>

                {/* Single AI Fix Button */}
                <button
                  onClick={handleSingleAutoFix}
                  disabled={fixingSingle}
                  className="bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold text-xs px-4 py-2.5 rounded-xl transition-all shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {fixingSingle ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>AI Securing Code...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-yellow-300" />
                      <span>{currentFix ? "Regenerate AI Patch" : "⚡ Fix with Real AI"}</span>
                    </>
                  )}
                </button>
              </div>

              {/* Vulnerable Snippet Box */}
              <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-lg">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" /> Flagged Vulnerable Code
                  </span>
                </div>
                <div className="bg-[#0B0F19] p-4 rounded-xl border border-red-950/60 overflow-x-auto font-mono text-sm text-red-300">
                  <pre>{selectedFinding.code_snippet || "// Line preview unavailable"}</pre>
                </div>
              </div>

              {/* AI Auto-Remediation Studio */}
              {currentFix && (
                <div className="bg-gradient-to-b from-[#111827] to-[#0d1527] border border-emerald-900/50 rounded-2xl p-6 shadow-2xl relative">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                      <Wand2 className="w-4 h-4 text-emerald-400" /> AI Refactored Secure Patch
                    </span>
                    <button
                      onClick={() => copyToClipboard(currentFix.fixed_code)}
                      className="bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? "Copied!" : "Copy Code"}</span>
                    </button>
                  </div>

                  <div className="bg-[#060c14] p-4 rounded-xl border border-emerald-950 overflow-x-auto font-mono text-sm text-emerald-300 mb-4 shadow-inner">
                    <pre>{currentFix.fixed_code}</pre>
                  </div>

                  <div className="space-y-3 text-xs leading-relaxed">
                    <div>
                      <h5 className="font-bold text-gray-300 uppercase tracking-wider mb-1">What the AI Changed:</h5>
                      <p className="text-gray-400 bg-[#0B0F19] p-3 rounded-lg border border-gray-800">
                        {currentFix.explanation}
                      </p>
                    </div>

                    {currentFix.principles && (
                      <div>
                        <h5 className="font-bold text-gray-300 uppercase tracking-wider mb-1">Security Principles Enforced:</h5>
                        <ul className="list-disc list-inside space-y-1 text-gray-400 bg-[#0B0F19] p-3 rounded-lg border border-gray-800">
                          {currentFix.principles.map((rule: string, i: number) => (
                            <li key={i}>{rule}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* AI Guidance Card with Restored Reference Link */}
              <div className="bg-[#111827] border border-blue-900/40 rounded-2xl p-6 shadow-xl relative overflow-hidden">
                <div className="flex items-center gap-2 text-blue-400 mb-4 font-bold text-base">
                  <BookOpen className="w-5 h-5" />
                  AI Context: {selectedFinding.educational_guide?.title || selectedFinding.rule_id}
                </div>

                <div className="space-y-4 text-sm leading-relaxed">
                  <div>
                    <h4 className="font-bold text-gray-400 text-[11px] uppercase tracking-wider mb-1.5">1. What Went Wrong?</h4>
                    <p className="text-gray-300 bg-[#0B0F19] p-3.5 rounded-xl border border-gray-800">
                      {selectedFinding.educational_guide?.explanation}
                    </p>
                  </div>

                  <div>
                    <h4 className="font-bold text-gray-400 text-[11px] uppercase tracking-wider mb-1.5">2. Threat Scenario</h4>
                    <p className="text-gray-300 bg-[#0B0F19] p-3.5 rounded-xl border border-gray-800">
                      {selectedFinding.educational_guide?.risk}
                    </p>
                  </div>

                  {/* Restored: Official Security Specification Link */}
                  {selectedFinding.educational_guide?.reference && (
                    <div className="pt-2 border-t border-gray-800/60">
                      <a
                        href={selectedFinding.educational_guide.reference}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-blue-400 hover:text-blue-300 hover:underline inline-flex items-center gap-1.5 font-medium transition-colors"
                      >
                        <span>Read official security specification &rarr;</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="bg-[#111827] border border-gray-800 rounded-2xl p-12 text-center text-gray-500">
              Select a finding from the left panel to inspect code and generate AI patches.
            </div>
          )}
        </div>
      </div>

      {/* Report Modal Viewer */}
      {reportModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-gray-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-5 border-b border-gray-800 flex justify-between items-center bg-[#131d33]">
              <div className="flex items-center gap-2 text-white font-bold text-base">
                <FileText className="w-5 h-5 text-blue-400" />
                <span>PEGASUS Security Remediation Audit Report</span>
              </div>
              <div className="flex items-center gap-3">
                <a
                  href={`${API_URL}/api/scans/${id}/download-report`}
                  download
                  className="bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" /> Download (.md)
                </a>
                <button
                  onClick={() => setReportModalOpen(false)}
                  className="text-gray-400 hover:text-white p-1"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto flex-1 font-mono text-xs leading-relaxed text-gray-300 bg-[#0B0F19]">
              {loadingReport ? (
                <div className="text-center py-12 text-gray-500">Generating report summary...</div>
              ) : (
                <pre className="whitespace-pre-wrap">{reportMarkdown}</pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}