"use client";

import React, { useState, useEffect } from "react";
import axios from "axios";
import { 
  UploadCloud, 
  ArrowRight, 
  Clock, 
  ShieldCheck, 
  ShieldAlert, 
  FileCode, 
  Sparkles,
  CheckCircle2,
  AlertCircle
} from "lucide-react";

export default function Dashboard() {
  const [projects, setProjects] = useState<any[]>([]);
  const [projectName, setProjectName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const fetchProjects = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/projects`);
      setProjects(res.data);
    } catch (e) {
      console.error("Failed to load projects", e);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !projectName.trim()) return;

    setUploading(true);
    setErrorMessage(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(
        `${API_URL}/api/projects/upload?project_name=${encodeURIComponent(projectName.trim())}`,
        formData
      );
      setProjectName("");
      setFile(null);
      window.location.href = `/scan/${res.data.scan_id}`;
    } catch (err: any) {
      setErrorMessage(
        err.response?.data?.detail || "Upload failed. Please ensure you upload a valid .zip repository archive."
      );
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-10">
      {/* Pegasus Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#111827] via-[#131d33] to-[#111827] border border-gray-800 p-8 shadow-xl">
        <div className="relative z-10 flex flex-col md:flex-row items-center gap-6">
          {/* Pegasus Logo */}
          <div className="w-24 h-24 rounded-2xl bg-white p-2.5 flex-shrink-0 flex items-center justify-center shadow-2xl ring-4 ring-blue-500/20">
            <img
              src="/pegasus-logo-design-free-vector.webp"
              alt="Pegasus Logo"
              className="w-full h-full object-contain"
            />
          </div>

          <div className="text-center md:text-left space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-950/80 border border-blue-800/80 text-blue-400 text-xs font-semibold uppercase tracking-wider">
              <Sparkles className="w-3.5 h-3.5" /> Next-Gen Secure Intelligence
            </div>
            <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
              PEGASUS Code Review & Forensics
            </h1>
            <p className="text-gray-400 max-w-2xl text-sm sm:text-base leading-relaxed">
              Automated Static Analysis (SAST), digital forensics heuristics, secret detection, and interactive AI-driven guidance tailored for developers and cybersecurity learners.
            </p>
          </div>
        </div>

        {/* Ambient background glow */}
        <div className="absolute -top-12 -right-12 w-64 h-64 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      </div>

      {/* Upload Section */}
      <div className="bg-[#111827] border border-gray-800 rounded-2xl p-7 shadow-lg">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-bold text-white flex items-center gap-2.5">
            <UploadCloud className="text-blue-400 w-5 h-5" /> Start a New Intelligence Scan
          </h2>
          <span className="text-xs text-gray-500 font-mono">Format: .zip source archive</span>
        </div>

        {errorMessage && (
          <div className="mb-5 p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-3">
            <AlertCircle className="w-5 h-5 flex-shrink-0 text-red-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleUpload} className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Project Name Field */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
                Project / Repository Name
              </label>
              <input
                type="text"
                required
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="e.g., Payment-Gateway-Service"
                className="w-full bg-[#0B0F19] border border-gray-700 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              />
            </div>

            {/* Archive Upload Field */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
                Repository Archive (.zip)
              </label>
              <div className="relative">
                <input
                  type="file"
                  required
                  accept=".zip"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="w-full text-sm text-gray-400 file:mr-4 file:py-2.5 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700 cursor-pointer bg-[#0B0F19] border border-gray-700 rounded-xl p-1.5 focus:outline-none"
                />
              </div>
              {file && (
                <p className="mt-1.5 text-xs text-gray-400 flex items-center gap-1 font-mono">
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                  Selected: <span className="text-gray-200 font-semibold">{file.name}</span> ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                </p>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={uploading || !file || !projectName.trim()}
            className="w-full bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold py-3.5 rounded-xl transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {uploading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Extracting Archive & Executing Intelligence Engines...</span>
              </>
            ) : (
              <>
                <FileCode className="w-4 h-4" />
                <span>Upload & Initiate Deep Security Scan</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Project Audit History */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" /> Recent Security Audits
          </h3>
          <span className="text-xs text-gray-500 font-mono">Total Projects: {projects.length}</span>
        </div>

        {projects.length === 0 ? (
          <div className="bg-[#111827] border border-gray-800 rounded-2xl p-12 text-center text-gray-500">
            <UploadCloud className="w-12 h-12 mx-auto text-gray-600 mb-3" />
            <p className="text-base font-medium text-gray-400">No project audits recorded yet.</p>
            <p className="text-xs text-gray-600 mt-1">Upload your first repository archive above to generate an audit report.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {projects.map((proj) => {
              const latestScan = proj.scans?.[0];
              const grade = latestScan?.grade || "N/A";

              return (
                <div 
                  key={proj.id} 
                  className="bg-[#111827] border border-gray-800 hover:border-gray-700 rounded-2xl p-6 flex flex-col justify-between transition-all group shadow-md"
                >
                  <div>
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="font-bold text-base text-white group-hover:text-blue-400 transition-colors line-clamp-1">
                        {proj.name}
                      </h4>
                      {latestScan && (
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-black tracking-wide border ${
                          grade === "A" ? "bg-green-950/80 text-green-400 border-green-700" :
                          grade === "B" ? "bg-blue-950/80 text-blue-400 border-blue-700" :
                          grade === "C" ? "bg-yellow-950/80 text-yellow-400 border-yellow-700" :
                          "bg-red-950/80 text-red-400 border-red-700"
                        }`}>
                          Grade {grade}
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-gray-500 flex items-center gap-1.5 mb-4">
                      <Clock className="w-3.5 h-3.5 text-gray-600" /> {new Date(proj.created_at).toLocaleDateString()} at {new Date(proj.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>

                    {latestScan && (
                      <div className="bg-[#0B0F19] rounded-xl p-3 border border-gray-800/80 space-y-1.5 text-xs text-gray-400 mb-5">
                        <div className="flex justify-between">
                          <span>Status:</span>
                          <span className={`font-mono font-semibold uppercase ${
                            latestScan.status === "COMPLETED" ? "text-green-400" : 
                            latestScan.status === "FAILED" ? "text-red-400" : "text-yellow-400"
                          }`}>
                            {latestScan.status}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span>Posture Score:</span>
                          <span className="text-white font-bold font-mono">
                            {latestScan.risk_score} / 100
                          </span>
                        </div>
                      </div>
                    )}
                  </div>

                  {latestScan && (
                    <a
                      href={`/scan/${latestScan.id}`}
                      className="inline-flex items-center justify-between text-xs font-semibold text-blue-400 hover:text-blue-300 bg-blue-950/30 hover:bg-blue-950/60 border border-blue-900/40 rounded-xl px-4 py-2.5 transition-all"
                    >
                      <span>Explore Findings & AI Guidance</span>
                      <ArrowRight className="w-3.5 h-3.5 ml-1 transition-transform group-hover:translate-x-1" />
                    </a>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}