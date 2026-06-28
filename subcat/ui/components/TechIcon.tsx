import { techIconUrl } from "@/lib/common";
import { Tooltip } from "@/components/ui/tooltip";

// A single technology icon (Wappalyzer icon set, served locally). A monogram
// chip shows as the base; the real icon loads over it when one exists.
// (Literal h-5/w-5 classes so Tailwind's JIT keeps them.)
export function TechIcon({
  tech,
  tip = true,
  boxed = false,
}: {
  tech: string;
  tip?: boolean;
  boxed?: boolean;
}) {
  const url = techIconUrl(tech);
  const icon = (
    <span className="relative inline-flex h-5 w-5">
      <span className="absolute inset-0 flex items-center justify-center rounded bg-secondary text-[10px] font-bold text-muted-foreground">
        {(tech[0] || "?").toUpperCase()}
      </span>
      {url && (
        <img
          src={url}
          alt={tech}
          loading="lazy"
          className="relative h-5 w-5 object-contain opacity-0 transition-opacity"
          onLoad={(e) => {
            // Icon loaded — reveal it and hide the monogram behind it, so the
            // monogram's background doesn't show through transparent icon areas.
            e.currentTarget.style.opacity = "1";
            const mono = e.currentTarget.previousElementSibling as HTMLElement | null;
            if (mono) mono.style.display = "none";
          }}
          onError={(e) => (e.currentTarget.style.display = "none")}
        />
      )}
    </span>
  );
  // Boxed: same bordered chip as the modal's TechChip, but icon-only (no label).
  const node = boxed ? (
    <span className="inline-flex items-center justify-center rounded-md border bg-secondary/40 p-1">
      {icon}
    </span>
  ) : (
    icon
  );
  return tip ? <Tooltip content={tech}>{node}</Tooltip> : node;
}

// Icon + label chip, for the detail view. The whole chip is the tooltip target.
export function TechChip({ tech }: { tech: string }) {
  return (
    <Tooltip content={tech}>
      <span className="inline-flex items-center gap-1.5 rounded-md border bg-secondary/40 px-2 py-1 text-xs">
        <TechIcon tech={tech} tip={false} />
        {tech}
      </span>
    </Tooltip>
  );
}
