import { Button } from "@/components/ui/button";

interface Props {
  page: number;
  pages: number;
  pageSize: number;
  onPage: (p: number) => void;
  onPageSize: (n: number) => void;
}

export function Pager({ page, pages, pageSize, onPage, onPageSize }: Props) {
  if (pages <= 1) return null;
  const start = Math.max(0, Math.min(page - 2, pages - 5));
  const nums = Array.from({ length: Math.min(5, pages) }, (_, i) => start + i);

  return (
    <div className="flex flex-wrap items-center gap-3 px-6 pb-8 pt-2">
      <select
        value={pageSize}
        onChange={(e) => onPageSize(Number(e.target.value))}
        className="h-9 rounded-md border border-input bg-background px-2 text-sm"
      >
        {[8, 12, 24, 48, 96].map((n) => (
          <option key={n} value={n}>
            {n}
          </option>
        ))}
      </select>
      <div className="mx-auto flex items-center gap-1.5">
        <Button variant="outline" size="sm" onClick={() => onPage(0)} disabled={page <= 0}>
          First
        </Button>
        <Button variant="outline" size="sm" onClick={() => onPage(page - 1)} disabled={page <= 0}>
          &lsaquo;
        </Button>
        {nums.map((i) => (
          <Button
            key={i}
            variant={i === page ? "default" : "outline"}
            size="sm"
            onClick={() => onPage(i)}
          >
            {i + 1}
          </Button>
        ))}
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPage(page + 1)}
          disabled={page >= pages - 1}
        >
          &rsaquo;
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPage(pages - 1)}
          disabled={page >= pages - 1}
        >
          Last
        </Button>
      </div>
    </div>
  );
}
