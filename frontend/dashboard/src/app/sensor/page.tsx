import SensorTable from "@/components/sensor/SensorTable";
import { sensors } from "@/data/sensor/sensor-data";
import SensorLogViewer from "@/components/sensor/SensorLogViewer";

export default function SensorPage() {
  return (
    <div className="p-6 space-y-8">
{/*
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {sensors.map((s) => (
          <SensorCard key={s.id} sensor={s} />
        ))}
      </div>
*/}

      {/* Detailed Table */}
      {/*<SensorTable sensors={sensors} />*/}

      <div className="mt-8">
        <SensorLogViewer />
      </div>
    </div>
  );
}
