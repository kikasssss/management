import Container from "@/components/container";
import { TopNav } from "@/components/nav";

export default function RuleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <TopNav title="Rule Management" />
      <main>
        <Container>{children}</Container>
      </main>
    </>
  );
}
