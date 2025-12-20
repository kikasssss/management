export default function RuleTable({ rules }: { rules: RuleSetInfo[] }) {
  return (
    <table className="w-full border text-sm bg-white rounded-lg shadow-sm">
      <thead className="bg-gray-50">
        <tr>
          <th className="px-3 py-2 text-left">SID</th>
          <th className="px-3 py-2 text-left">MESSAGE</th>
          <th className="px-3 py-2 text-left">CATEGORY</th>
          <th className="px-3 py-2 text-left">STATUS</th>
          <th className="px-3 py-2 text-left">COUNT</th>
          <th className="px-3 py-2 text-left">FULL LOG</th>
          <th className="px-3 py-2 text-left">APPLY</th>
        </tr>
      </thead>

      <tbody>
        {rules.map((rule) => (
          <tr key={rule.sid} className="border-t hover:bg-gray-50">
            <td className="px-3 py-2">{rule.sid}</td>
            <td className="px-3 py-2">{rule.msg}</td>
            <td className="px-3 py-2">{rule.category}</td>

            <td
              className={`px-3 py-2 font-bold ${
                rule.status === "active" ? "text-green-600" : "text-gray-400"
              }`}
            >
              {rule.status}
            </td>

            <td className="px-3 py-2">{rule.count}</td>

            <td className="px-3 py-2 text-blue-600 underline cursor-pointer">
              View
            </td>

            <td className="px-3 py-2 text-blue-600 underline cursor-pointer">
              Apply
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
