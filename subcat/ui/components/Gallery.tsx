import { useEffect, useMemo, useRef, useState } from "react";
import { Shot, ScanMeta, imageBase } from "@/lib/common";
import { useUrlState } from "@/hooks/useUrlState";
import { ShotCard } from "./ShotCard";
import { Toolbar } from "./Toolbar";
import { Pager } from "./Pager";
import { DetailModal } from "./DetailModal";

interface Props {
  scan: ScanMeta;
  shots: Shot[];
  query: string;
}

const toSet = (s: string) => new Set(s.split(",").filter(Boolean));
const toTechSet = (s: string) => new Set(s.split("~").filter(Boolean));

export function Gallery({ scan, shots, query }: Props) {
  const q = query;
  const [statusStr, setStatusStr] = useUrlState("status", "");
  const [techStr, setTechStr] = useUrlState("tech", "");
  const [failedStr, setFailedStr] = useUrlState("failed", "1");
  const [pageStr, setPageStr] = useUrlState("page", "1");
  const [psStr, setPsStr] = useUrlState("ps", "12");
  const [active, setActive] = useState<Shot | null>(null);

  // Reset to the first page when the search query changes (but keep a
  // deep-linked page on initial mount).
  const firstRun = useRef(true);
  useEffect(() => {
    if (firstRun.current) {
      firstRun.current = false;
      return;
    }
    setPageStr("1");
  }, [query]);

  const statuses = toSet(statusStr);
  const techs = toTechSet(techStr);
  const showFailed = failedStr !== "0";
  const page = Math.max(0, parseInt(pageStr) - 1 || 0);
  const pageSize = parseInt(psStr) || 12;

  const codes = useMemo(
    () => [...new Set(shots.filter((s) => s.status != null).map((s) => s.status as number))].sort((a, b) => a - b),
    [shots]
  );
  const allTechs = useMemo(
    () => [...new Set(shots.flatMap((s) => s.technologies || []))].sort((a, b) => a.localeCompare(b)),
    [shots]
  );

  const filtered = useMemo(() => {
    const needle = q.toLowerCase();
    return shots.filter((s) => {
      if (!showFailed && s.status == null) return false;
      if (statuses.size && (s.status == null || !statuses.has(String(s.status)))) return false;
      if (techs.size && !(s.technologies || []).some((t) => techs.has(t))) return false;
      if (needle) {
        const hay = [s.input, s.title, s.server, s.final_url, s.status, (s.technologies || []).join(" ")]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [shots, q, statusStr, techStr, failedStr]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const clamped = Math.min(page, pages - 1);
  const slice = filtered.slice(clamped * pageSize, clamped * pageSize + pageSize);

  const setPage = (p: number) => {
    setPageStr(String(Math.max(0, Math.min(p, pages - 1)) + 1));
    window.scrollTo(0, 0);
  };
  const toggle = (set: Set<string>, v: string, sep: string, save: (s: string) => void) => {
    set.has(v) ? set.delete(v) : set.add(v);
    save([...set].join(sep));
    setPage(0);
  };

  return (
    <>
      <div className="px-6 pt-5">
        <Toolbar
          codes={codes}
          techs={allTechs}
          selectedStatuses={statuses}
          selectedTechs={techs}
          showFailed={showFailed}
          hasFilters={statuses.size > 0 || techs.size > 0 || !showFailed}
          shown={filtered.length}
          total={shots.length}
          canPrev={clamped > 0}
          canNext={clamped < pages - 1}
          onToggleStatus={(c) => toggle(statuses, c, ",", setStatusStr)}
          onToggleTech={(t) => toggle(techs, t, "~", setTechStr)}
          onToggleFailed={() => {
            setFailedStr(showFailed ? "0" : "1");
            setPage(0);
          }}
          onClear={() => {
            setStatusStr("");
            setTechStr("");
            setFailedStr("1");
            setPage(0);
          }}
          onPrev={() => setPage(clamped - 1)}
          onNext={() => setPage(clamped + 1)}
        />
      </div>

      {slice.length ? (
        <div className="grid gap-6 p-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {slice.map((s) => (
            <ShotCard key={s.input} shot={s} imageBase={imageBase(scan.id)} onClick={() => setActive(s)} />
          ))}
        </div>
      ) : (
        <div className="p-20 text-center text-muted-foreground">no matching hosts</div>
      )}

      <Pager
        page={clamped}
        pages={pages}
        pageSize={pageSize}
        onPage={setPage}
        onPageSize={(n) => {
          setPsStr(String(n));
          setPage(0);
        }}
      />

      <DetailModal shot={active} scanId={scan.id} onClose={() => setActive(null)} />
    </>
  );
}
