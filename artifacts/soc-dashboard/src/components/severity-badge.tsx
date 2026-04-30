import { Badge } from "@/components/ui/badge";

type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

export function SeverityBadge({ severity }: { severity?: Severity | null }) {
  if (!severity) return null;
  const s = severity.toLowerCase();
  
  let bg = "bg-muted";
  let text = "text-muted-foreground";

  if (s === "critical") {
    bg = "bg-[hsl(var(--color-severity-critical))]";
    text = "text-destructive-foreground";
  } else if (s === "high") {
    bg = "bg-[hsl(var(--color-severity-high))]";
    text = "text-destructive-foreground";
  } else if (s === "medium") {
    bg = "bg-[hsl(var(--color-severity-medium))]";
    text = "text-background";
  } else if (s === "low") {
    bg = "bg-[hsl(var(--color-severity-low))]";
    text = "text-background";
  } else if (s === "info") {
    bg = "bg-[hsl(var(--color-severity-info))]";
    text = "text-background";
  }

  return (
    <Badge className={`${bg} ${text} hover:${bg} font-mono uppercase text-xs font-bold`}>
      {s}
    </Badge>
  );
}
