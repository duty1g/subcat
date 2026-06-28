import * as React from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  side?: "top" | "bottom";
  className?: string;        // styles the tooltip bubble
  wrapperClassName?: string; // styles the wrapper around the trigger
}

interface Pos {
  x: number;
  y: number;
  side: "top" | "bottom";
}

// Lightweight, dependency-free tooltip (no Radix — matches the custom Popover).
// Renders into a body portal with fixed positioning so it is never clipped by a
// card's `overflow-hidden`. Fades + slides in with a small arrow; flips to the
// opposite side when there isn't room.
export function Tooltip({ content, children, side = "top", className, wrapperClassName }: TooltipProps) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const [pos, setPos] = React.useState<Pos | null>(null);

  if (content == null || content === "") return <>{children}</>;

  const show = () => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    // Flip to the other side when the preferred one would overflow the viewport.
    let s = side;
    if (s === "top" && r.top < 56) s = "bottom";
    else if (s === "bottom" && r.bottom > window.innerHeight - 56) s = "top";
    const x = Math.min(Math.max(r.left + r.width / 2, 12), window.innerWidth - 12);
    const y = s === "top" ? r.top - 8 : r.bottom + 8;
    setPos({ x, y, side: s });
  };
  const hide = () => setPos(null);

  return (
    <span
      ref={ref}
      className={cn("relative inline-flex", wrapperClassName)}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {children}
      {pos &&
        createPortal(
          <span
            role="tooltip"
            style={{ left: pos.x, top: pos.y }}
            className={cn(
              "pointer-events-none fixed z-[100] max-w-xs whitespace-nowrap rounded-md border border-border/70",
              "bg-popover px-2 py-1 text-xs font-medium leading-none text-popover-foreground shadow-lg",
              pos.side === "top" ? "tip-anim-top" : "tip-anim-bottom",
              className
            )}
          >
            {content}
            <span
              className={cn(
                "absolute left-1/2 h-2 w-2 -translate-x-1/2 rotate-45 border-border/70 bg-popover",
                pos.side === "top" ? "top-full -mt-1 border-b border-r" : "bottom-full -mb-1 border-t border-l"
              )}
            />
          </span>,
          document.body
        )}
    </span>
  );
}
