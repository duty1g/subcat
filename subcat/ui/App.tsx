import { useEffect, useState } from "react";
import { ChevronRightIcon } from "lucide-react";
import logoUrl from "@/assets/logo.png";
import { Shot, ScanMeta, getScans, getScan } from "@/lib/common";
import { Input } from "@/components/ui/input";
import { ThemeToggle } from "@/components/ThemeToggle";
import { ScanList } from "@/components/ScanList";
import { Gallery } from "@/components/Gallery";
import { useUrlState } from "@/hooks/useUrlState";

export default function App() {
  const [scans, setScans] = useState<ScanMeta[] | null>(null);
  const [scanId, setScanId] = useUrlState("scan", "");
  const [shots, setShots] = useState<Shot[] | null>(null);
  const [q, setQ] = useUrlState("q", "");

  // Load scan index once, and set the favicon to the subcat logo.
  useEffect(() => {
    getScans().then(setScans).catch(() => setScans([]));
    let link = document.querySelector<HTMLLinkElement>("link[rel='icon']");
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.appendChild(link);
    }
    link.href = logoUrl;
  }, []);

  // Auto-open when there is exactly one scan.
  useEffect(() => {
    if (scans && !scanId && scans.length === 1) setScanId(scans[0].id);
  }, [scans, scanId]);

  // Load the active scan's results.
  useEffect(() => {
    if (!scanId) {
      setShots(null);
      return;
    }
    setShots(null);
    getScan(scanId).then(setShots).catch(() => setShots([]));
  }, [scanId]);

  const meta = scans?.find((s) => s.id === scanId);
  const inGallery = !!scanId;

  return (
    <div className="min-h-screen">
      <nav className="sticky top-0 z-40 flex items-center gap-4 border-b bg-background px-5 py-3">
        <div
          className="flex cursor-pointer items-center gap-2 text-base font-bold tracking-tight"
          onClick={() => setScanId("")}
        >
          <img src={logoUrl} alt="subcat" className="h-8 w-auto" />
          <span>
            sub<span className="text-primary">cat</span>
          </span>
        </div>
        {inGallery && (
          <span className="flex items-center gap-1 text-sm text-muted-foreground">
            <ChevronRightIcon className="h-4 w-4" />
            <b className="text-foreground">{meta?.domain || scanId}</b>
            {scans && scans.length > 1 && (
              <span
                className="ml-2 cursor-pointer opacity-70 hover:opacity-100"
                onClick={() => setScanId("")}
              >
                [all scans]
              </span>
            )}
          </span>
        )}
        <div className="ml-auto flex items-center gap-2.5">
          {inGallery && (
            <Input
              placeholder="Search…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="w-56"
            />
          )}
          <ThemeToggle />
        </div>
      </nav>

      {scans === null ? (
        <div className="p-20 text-center text-muted-foreground">loading…</div>
      ) : inGallery ? (
        shots === null ? (
          <div className="p-20 text-center text-muted-foreground">loading…</div>
        ) : meta ? (
          <Gallery key={scanId} scan={meta} shots={shots} query={q} />
        ) : (
          <div className="p-20 text-center text-muted-foreground">scan not found</div>
        )
      ) : (
        <ScanList scans={scans} onOpen={setScanId} />
      )}
    </div>
  );
}
