"use client";
import type { AttackChain } from "@/types/types";

interface AttackChainViewProps {
  chains: AttackChain[];
}
export default function AttackChainView({ chains }: AttackChainViewProps) {
  return (
    <section className="rounded-xl border bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold">AI Attack Chain Detection</h2>

      {chains.map((chain) => (
        <div key={chain.id} className="mt-4 space-y-2">
          <p className="text-sm text-gray-500">
            {chain.startTime} → {chain.endTime}
          </p>

          <div className="flex items-center gap-2 flex-wrap">
            {chain.tactics.map((tactic, index) => (
              <div key={index} className="flex items-center gap-2">
                <span className="rounded-full bg-indigo-50 text-indigo-700 px-3 py-1 text-xs font-medium">
                  {tactic}
                </span>

                {index < chain.tactics.length - 1 && (
                  <span className="text-gray-400">→</span>
                )}
              </div>
            ))}
          </div>

          <p className="text-xs text-gray-600">
            Confidence:{" "}
            <span className="text-indigo-600 font-medium">
              {chain.confidence}%
            </span>
          </p>
        </div>
      ))}
    </section>
  );
}
