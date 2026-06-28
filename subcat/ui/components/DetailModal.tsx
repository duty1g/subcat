import { useEffect } from "react";
import { XIcon } from "lucide-react";
import { Shot, imageBase } from "@/lib/common";
import { TechChip } from "./TechIcon";

interface Props {
  shot: Shot | null;
  scanId: string;
  onClose: () => void;
}

export function DetailModal({ shot, scanId, onClose }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!shot) return null;
  const url = shot.url || shot.final_url || "//" + shot.input;
  const src = shot.screenshot ? imageBase(scanId) + shot.screenshot : "";

  const techs = shot.technologies || [];
  const rows: [string, any][] = [
    ["Host", shot.input],
    ["Status", shot.status],
    ["Title", shot.title],
    ["URL", shot.url],
    ["Final URL", shot.final_url],
    ["Server", shot.server],
    ["Error", shot.error],
  ];

  return (
    <div
      className="fixed inset-0 z-50 overflow-auto bg-black/70 p-8"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="mx-auto max-w-5xl overflow-hidden rounded-xl border bg-card">
        <div className="flex items-start justify-between gap-4 border-b p-3">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold">{shot.title || shot.input}</div>
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="block truncate text-xs text-blue-400 hover:underline"
            >
              {url}
            </a>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 text-muted-foreground hover:text-foreground"
          >
            <XIcon className="h-5 w-5" />
          </button>
        </div>
        {src && <img src={src} alt={shot.input} className="w-full bg-black" />}
        <div className="grid grid-cols-[130px_1fr] gap-x-4 gap-y-2 p-4 text-sm">
          {rows
            .filter(([, v]) => v != null && v !== "")
            .map(([k, v]) => {
              const isLink = k === "URL" || k === "Final URL";
              return (
                <div key={k} className="contents">
                  <div className="text-muted-foreground">{k}</div>
                  {isLink ? (
                    <a
                      href={String(v)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="break-all text-blue-400 hover:underline"
                    >
                      {String(v)}
                    </a>
                  ) : (
                    <div className="break-all">{String(v)}</div>
                  )}
                </div>
              );
            })}
          {techs.length > 0 && (
            <div className="contents">
              <div className="text-muted-foreground">Technologies</div>
              <div className="flex flex-wrap gap-1.5">
                {techs.map((t) => (
                  <TechChip key={t} tech={t} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
