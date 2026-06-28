import { ScanMeta } from "@/lib/common";
import { Card } from "@/components/ui/card";
import logoUrl from "@/assets/logo.png";

interface Props {
  scans: ScanMeta[];
  onOpen: (id: string) => void;
}

export function ScanList({ scans, onOpen }: Props) {
  if (!scans.length) {
    return (
      <div className="flex flex-col items-center gap-4 p-20 text-center text-muted-foreground">
        <img src={logoUrl} alt="subcat" className="h-20 w-auto opacity-80" />
        <div>no scans found</div>
      </div>
    );
  }
  return (
    <>
      <div className="flex flex-col items-center gap-3 px-6 pt-10 pb-2 text-center">
        <img src={logoUrl} alt="subcat" className="h-24 w-auto" />
        <p className="text-sm text-muted-foreground">
          {scans.length} scan{scans.length > 1 ? "s" : ""} · select one to view
        </p>
      </div>
      <div className="grid gap-4 p-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {scans.map((s) => (
        <Card
          key={s.id}
          onClick={() => onOpen(s.id)}
          className="cursor-pointer p-5 transition-all hover:shadow-lg"
        >
          <div className="truncate text-base font-bold">{s.domain || s.id}</div>
          <div className="mb-3 mt-1 truncate text-xs text-muted-foreground">
            {s.id}
            {s.created ? " · " + s.created.replace("T", " ") : ""}
          </div>
          <div className="flex gap-4 text-sm">
            <span>
              <b className="text-green-500">{s.alive || 0}</b> alive
            </span>
            <span className="text-muted-foreground">{s.total || 0} total</span>
          </div>
        </Card>
        ))}
      </div>
    </>
  );
}
