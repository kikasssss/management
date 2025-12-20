interface RuleFiltersProps {
  search: string;
  setSearch: (value: string) => void;
  status: string;
  setStatus: (value: string) => void;
}

export default function RuleFilters({ search, setSearch, status, setStatus }: RuleFiltersProps) {
  return (
    <div className="flex flex-col md:flex-row gap-3 p-4 border rounded-xl bg-white shadow-sm">
      <input
        type="text"
        placeholder="Search by SID, message, MITRE…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="border p-2 rounded-md flex-1"
      />

      <select
        value={status}
        onChange={(e) => setStatus(e.target.value)}
        className="border p-2 rounded-md"
      >
        <option value="all">All status</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
      </select>
    </div>
  );
}
