import Link from "next/link";
import type { ReactNode } from "react";

export default function Banner({
  className = "",
  children,
}: {
  className?: string;
  children?: ReactNode;
}) {
  return (
    <header
      className={`retro-banner flex w-full flex-wrap items-center justify-between gap-3 ${className}`}
    >
      <Link href="/" aria-label="Guardia home" className="guardia-logo-frame">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/guardia-logo.png" alt="Guardia" width={1254} height={1254} />
      </Link>
      <div>{children}</div>
    </header>
  );
}
