  export const priorityMap: Record<string, 1 | 2 | 3> = {
    High: 1,
    Medium: 2,
    Low: 3,
  } as const;

 export function priorityLabel(priority: 1 | 2 | 3) {
    return priority === 1 ? "High" : priority === 2 ? "Medium" : "Low";
  }

  export function priorityColor(priority: 1 | 2 | 3) {
    return priority === 1
      ? "bg-red-100 text-red-700"
      : priority === 2
      ? "bg-yellow-100 text-yellow-700"
      : "bg-blue-100 text-blue-700";
  }

  export function statusLabel(enabled: boolean) {
    return enabled ? "Enabled" : "Disabled";
  }

  export function statusColor(enabled: boolean) {
    return enabled ? "text-green-600" : "text-gray-400";
  }
