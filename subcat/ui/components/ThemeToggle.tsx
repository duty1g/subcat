import { useEffect, useState } from "react";
import { MoonIcon, SunIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ThemeToggle() {
  const [dark, setDark] = useState(true);

  useEffect(() => {
    let t = "dark";
    try {
      t = localStorage.getItem("subcat-theme") || "dark";
    } catch {}
    const isDark = t !== "light";
    setDark(isDark);
    document.documentElement.classList.toggle("dark", isDark);
  }, []);

  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("subcat-theme", next ? "dark" : "light");
    } catch {}
  };

  return (
    <Button variant="outline" size="icon" onClick={toggle} title="Toggle theme">
      {dark ? <SunIcon className="h-4 w-4" /> : <MoonIcon className="h-4 w-4" />}
    </Button>
  );
}
