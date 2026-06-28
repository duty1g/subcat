import { ClockIcon, ExternalLinkIcon } from "lucide-react";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shot, getStatusColor, relTime, statusLabel, absTime } from "@/lib/common";
import { TechIcon } from "./TechIcon";
import { Tooltip } from "@/components/ui/tooltip";

interface Props {
  shot: Shot;
  imageBase: string;
  onClick: () => void;
}

// A single gallery card — mirrors the gowitness card layout exactly.
export function ShotCard({ shot, imageBase, onClick }: Props) {
  const url = shot.url || shot.final_url || "//" + shot.input;
  const src = shot.screenshot ? imageBase + shot.screenshot : "";

  return (
    <Card
      onClick={onClick}
      className="group flex h-full cursor-pointer flex-col overflow-hidden transition-all hover:shadow-lg"
    >
      <CardContent className="relative flex-grow p-0">
        {src ? (
          <img
            src={src}
            alt={shot.input}
            loading="lazy"
            className="aspect-[16/9] w-full object-cover object-top transition-all duration-300 group-hover:scale-105"
          />
        ) : (
          <div className="flex aspect-[16/9] w-full items-center justify-center bg-muted text-xs text-muted-foreground">
            no screenshot
          </div>
        )}
        <Tooltip content={statusLabel(shot.status)} side="bottom" wrapperClassName="absolute right-2 top-2">
          <Badge className={getStatusColor(shot.status)}>
            {shot.status == null ? "dead" : shot.status}
          </Badge>
        </Tooltip>
        <Tooltip
          content="Open site in new tab"
          wrapperClassName="absolute bottom-2 right-2 opacity-0 transition-opacity group-hover:opacity-100"
        >
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
          >
            <ExternalLinkIcon className="h-5 w-5 text-white drop-shadow-lg" />
          </a>
        </Tooltip>
      </CardContent>

      <CardFooter className="flex flex-col items-start gap-1.5 p-3">
        <div className="w-full truncate text-base font-semibold">{shot.title || shot.input}</div>
        <div className="w-full truncate text-sm text-muted-foreground">{url}</div>
        <div className="mt-1 flex w-full items-center justify-between gap-2">
          <Tooltip content={absTime(shot.timestamp)}>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ClockIcon className="h-3.5 w-3.5" />
              <span>{relTime(shot.timestamp)}</span>
            </div>
          </Tooltip>
          <div className="flex flex-wrap justify-end gap-1">
            {(shot.technologies || []).slice(0, 12).map((tech) => (
              <TechIcon key={tech} tech={tech} boxed />
            ))}
          </div>
        </div>
      </CardFooter>
    </Card>
  );
}
