"use client";

import { useState, useEffect, useMemo } from "react";
import {
  fetchRuleSets,
  fetchActiveRuleSet,
  fetchSensors, // 👈 dùng cho Heartbeat
} from "@/lib/api";

import RuleTable from "@/components/rule/RuleTable";
import TIRuleTable from "@/components/rule/TIRuleTable";
import Heartbeat from "@/components/rule/Heartbeat";

import type { RuleSetInfo, SensorInfo } from "@/types/types";

export default function RulePage() {
  const [search, setSearch] = useState("");

  // ================================
  // SENSOR HEARTBEAT STATE
  // ================================
  const [sensors, setSensors] = useState<SensorInfo[]>([]);

  // ================================
  // RULESET STATE
  // ================================
  const [rulesFromBackend, setRulesFromBackend] = useState<RuleSetInfo[]>([]);

  // ================================
  // TI RULE STATE
  // ================================
  const [tiRules, setTiRules] = useState<any[]>([]);
  const [tiSearch, setTiSearch] = useState("");

  // ================================
  // IOC SEARCH STATE
  // ================================
  const [iocQuery, setIocQuery] = useState("");
  const [iocResult, setIocResult] = useState<any>(null);

  // ============================================================
  // LOAD SENSOR HEARTBEAT (MANAGER)
  // ============================================================
  useEffect(() => {
    async function loadSensors() {
      try {
        const data = await fetchSensors();
        setSensors(data.sensors || []);
      } catch (err) {
        console.error("FAILED LOAD SENSORS:", err);
      }
    }

    loadSensors();
    const interval = setInterval(loadSensors, 10000);
    return () => clearInterval(interval);
  }, []);

  // ============================================================
  // LOAD RULE SETS
  // ============================================================
  useEffect(() => {
    async function loadRuleSets() {
      try {
        const rules = await fetchRuleSets();
        const status = await fetchActiveRuleSet();
        const activeId = status.active_rule_set_id;

        const converted: RuleSetInfo[] = rules.map((item: any) => ({
          sid: item._id,
          msg: item.description ?? "No message",
          category: item.version,
          status: item._id === activeId ? "active" : "inactive",
          count: item.rule_count ?? 0,
        }));

        setRulesFromBackend(converted);
      } catch (error) {
        console.error("FAILED LOAD RULE SETS:", error);
      }
    }

    loadRuleSets();
  }, []);

  // ============================================================
  // LOAD TI RULES
  // ============================================================
  useEffect(() => {
    async function loadTiRules() {
      try {
        const res = await fetch("http://100.100.100.100:5000/rules");
        const json = await res.json();
        setTiRules(json.data || []);
      } catch (err) {
        console.error("FAILED LOAD TI RULES:", err);
      }
    }

    loadTiRules();
  }, []);

  // ============================================================
  // FILTER RULESETS
  // ============================================================
  const filteredRuleSets = useMemo(() => {
    const q = search.toLowerCase();
    return rulesFromBackend.filter(
      (r) =>
        r.sid.toString().includes(q) ||
        r.msg.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q)
    );
  }, [rulesFromBackend, search]);

  // ============================================================
  // FILTER TI RULES
  // ============================================================
  const filteredTiRules = useMemo(() => {
    const q = tiSearch.toLowerCase();
    return tiRules.filter((r) =>
      (r.content || "").toLowerCase().includes(q) ||
      (r.threat_id || "").toLowerCase().includes(q) ||
      (r.source || "").toLowerCase().includes(q) ||
      (r.version || "").toLowerCase().includes(q)
    );
  }, [tiRules, tiSearch]);

  // ============================================================
  // IOC SEARCH
  // ============================================================
  async function searchIOC() {
    if (!iocQuery.trim()) return;

    try {
      const res = await fetch(
        `http://100.100.100.100:5000/api/ioc/search?q=${iocQuery}`
      );
      const json = await res.json();
      setIocResult(json);
    } catch (err) {
      console.error("FAILED IOC SEARCH:", err);
    }
  }

  // ============================================================
  // RENDER
  // ============================================================
  return (
    <div className="space-y-10 p-6">

      {/* ================= SENSOR HEARTBEAT ================= */}
      <div className="p-4 border rounded-lg bg-white shadow">
        <h2 className="text-lg font-semibold mb-3">
          Connected Sensors (Rule Deployment)
        </h2>

        <Heartbeat sensors={sensors} />
      </div>

      {/* ================= IOC LOOKUP ================= */}
      <div className="space-y-4 p-4 border rounded-lg bg-white shadow">
        <h2 className="text-lg font-semibold">IOC Lookup</h2>

        <div className="flex gap-2">
          <input
            value={iocQuery}
            onChange={(e) => setIocQuery(e.target.value)}
            placeholder="Enter IP, domain, hash..."
            className="px-3 py-2 border rounded w-full"
          />
          <button
            onClick={searchIOC}
            className="px-4 py-2 bg-blue-600 text-white rounded"
          >
            Search
          </button>
        </div>

        {iocResult && (
          <pre className="bg-gray-100 p-4 rounded text-sm max-h-[300px] overflow-y-auto">
            {JSON.stringify(iocResult, null, 2)}
          </pre>
        )}
      </div>

      {/* ================= RULESETS ================= */}
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search rulesets..."
        className="px-3 py-2 border rounded w-full"
      />

      <div>
        <h2 className="text-lg font-semibold mb-2">Rule Sets</h2>
        <RuleTable rules={filteredRuleSets} />
      </div>

      {/* ================= TI RULES ================= */}
      <div className="mt-10">
        <h2 className="text-lg font-semibold mb-3">
          Threat Intelligence Rules
        </h2>

        <input
          value={tiSearch}
          onChange={(e) => setTiSearch(e.target.value)}
          placeholder="Search TI rules (IOC, content, source, version)..."
          className="px-3 py-2 border rounded w-full mb-4"
        />

        <TIRuleTable rules={filteredTiRules} />
      </div>
    </div>
  );
}
