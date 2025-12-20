import Container from "@/components/container";
import { TopNav } from "@/components/nav";

export default function SensorLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <TopNav title="Sensor Mangagement" />
      <main>
        <Container>{children}</Container>
      </main>
    </>
  );
}
