import { Gauge, type LucideIcon, MessagesSquare } from "lucide-react";

export type SiteConfig = typeof siteConfig;
export type Navigation = {
  icon: LucideIcon;
  name: string;
  href: string;
};

export const siteConfig = {
  title: "ThreatScope",
  description: "Intelligent Security Monitoring System",
};

export const navigations: Navigation[] = [
  {
    icon: Gauge,
    name: "Dashboard",
    href: "/",
  },
  {
    icon: MessagesSquare,
    name: "Sensor",
    href: "/sensor",
  },
  {
    icon: MessagesSquare,
    name: "Rule",
    href: "/rule",
  },
  {
    icon: MessagesSquare,
    name: "AI",
    href: "/ai",
  },
];
