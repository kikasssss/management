import Container from "@/components/container";
import { TopNav } from "@/components/nav";

export default function AILayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <TopNav title="AI Analysis" />
      <main>
        <Container>{children}</Container>
      </main>
    </>
  );
}
