"use client";

export default function TIRuleTable({ rules }) {
  return (
    <div className="max-h-[500px] overflow-y-auto border rounded-lg">
      <table className="w-full text-sm bg-white">
        <thead className="bg-gray-50 sticky top-0 z-10">
          <tr>
            <th className="px-3 py-2 text-left">SID</th>
            <th className="px-3 py-2 text-left">Source</th>
            <th className="px-3 py-2 text-left">Threat ID</th>
            <th className="px-3 py-2 text-left w-1/2">Rule Content</th>
          </tr>
        </thead>

        <tbody>
          {rules.map((r, i) => (
            <tr key={i} className="border-t hover:bg-gray-50">
              <td className="px-3 py-2">{r.sid || "N/A"}</td>
              <td className="px-3 py-2">{r.source}</td>
              <td className="px-3 py-2">{r.threat_id}</td>

              {/* RULE CONTENT CÓ SCROLL RIÊNG */}
              <td className="px-3 py-2">
                <div className="max-h-[120px] overflow-y-auto p-2 bg-gray-100 rounded text-xs font-mono whitespace-pre-wrap">
                  {r.content}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
