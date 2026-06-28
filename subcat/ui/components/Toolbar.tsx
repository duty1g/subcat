import { ChevronLeftIcon, ChevronRightIcon, FilterIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Popover } from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { getStatusColor } from "@/lib/common";

interface Props {
  codes: number[];
  techs: string[];
  selectedStatuses: Set<string>;
  selectedTechs: Set<string>;
  showFailed: boolean;
  hasFilters: boolean;
  shown: number;
  total: number;
  canPrev: boolean;
  canNext: boolean;
  onToggleStatus: (code: string) => void;
  onToggleTech: (tech: string) => void;
  onToggleFailed: () => void;
  onClear: () => void;
  onPrev: () => void;
  onNext: () => void;
}

export function Toolbar(p: Props) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg">
      <div className="flex flex-wrap items-center gap-2">
        <Popover
          trigger={
            <Button variant="outline" size="sm" className="h-9">
              <FilterIcon className="h-4 w-4" />
              {p.selectedTechs.size ? `${p.selectedTechs.size} selected` : "Technologies"}
            </Button>
          }
        >
          {p.techs.length ? (
            p.techs.map((t) => (
              <label
                key={t}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent"
              >
                <input
                  type="checkbox"
                  checked={p.selectedTechs.has(t)}
                  onChange={() => p.onToggleTech(t)}
                />
                {t}
              </label>
            ))
          ) : (
            <div className="px-2 py-1.5 text-sm text-muted-foreground">none detected</div>
          )}
        </Popover>

        {p.codes.map((c) => {
          const on = p.selectedStatuses.has(String(c));
          return (
            <Button
              key={c}
              variant="outline"
              size="sm"
              aria-pressed={on}
              className={
                "h-9 transition-colors " +
                (on
                  ? "border-primary/40 bg-accent text-accent-foreground shadow-inner"
                  : "opacity-70 hover:opacity-100")
              }
              onClick={() => p.onToggleStatus(String(c))}
            >
              <Badge className={`${getStatusColor(c)} px-1.5`}>{c}</Badge>
            </Button>
          );
        })}

        <label className="flex cursor-pointer select-none items-center gap-2 pl-2 text-sm">
          <Switch checked={p.showFailed} onCheckedChange={p.onToggleFailed} />
          Show failed
        </label>

        {p.hasFilters && (
          <Button
            variant="ghost"
            size="sm"
            className="h-9 text-muted-foreground hover:text-foreground"
            onClick={p.onClear}
          >
            <XIcon className="h-4 w-4" />
            Clear filters
          </Button>
        )}
      </div>

      <div className="flex items-center gap-3">
        <span className="text-xs text-muted-foreground">
          {p.shown} / {p.total} hosts
        </span>
        <Button variant="outline" size="icon" onClick={p.onPrev} disabled={!p.canPrev}>
          <ChevronLeftIcon className="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" onClick={p.onNext} disabled={!p.canNext}>
          <ChevronRightIcon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
