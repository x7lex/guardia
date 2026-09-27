export type RetroIconName =
  | "file"
  | "overview"
  | "risk"
  | "sections"
  | "signature"
  | "warning"
  | "imports"
  | "close"
  | "maximize"
  | "restore"
  | "trash"
  | "copy"
  | "download"
  | "home"
  | "hourglass"
  | "happy"
  | "neutral"
  | "unhappy"
  | "speaker"
  | "muted"
  | "chevron-left"
  | "chevron-right"
  | "controls"
  | "gear";

const paths: Record<RetroIconName, string> = {
  gear: "M6 0h4v3h2V1h2v2h1v2h-2v1h3v4h-3v2h2v2h-2v1h-2v-2h-1v3H6v-3H4v2H2v-2H1v-2h2v-1H0V6h3V4H1V2h2V1h2v2h1V0zM6 5v1H5v4h1v1h4v-1h1V6h-1V5H6z",
  speaker:
    "M1 6h3l4-4v12l-4-4H1V6zm9-1h1v1h1v4h-1v1h-1V9h1V7h-1V5zm3-3h1v2h1v8h-1v2h-1v-3h1V5h-1V2z",
  muted:
    "M1 6h3l4-4v12l-4-4H1V6zm9-1h2v2h1V5h2v2h-1v2h1v2h-2V9h-1v2h-2V9h1V7h-1V5z",
  "chevron-left":
    "M10 2h2v2h-2v2H8v2H6v2h2v2h2v2h2v2h-2v-2H8v-2H6v-2H4V8h2V6h2V4h2V2z",
  "chevron-right":
    "M4 2h2v2h2v2h2v2h2v2h-2v2H8v2H6v2H4v-2h2v-2h2v-2h2V8H8V6H6V4H4V2z",
  controls:
    "M2 1h1v4H1v4h1v6h1V9h2V5H3V1H2zm5 0h1v8H6v4h1v2h1v-2h2V9H8V1H7zm5 0h1v2h-2v4h1v8h1V7h2V3h-2V1h-1z",
  happy:
    "M5 0h6v1H5zM3 1h2v1H3zm8 0h2v1h-2zM2 2h1v1H2zm11 0h1v1h-1zM1 3h1v2H1zm13 0h1v2h-1zM0 5h1v6H0zm15 0h1v6h-1zM1 11h1v2H1zm13 0h1v2h-1zM2 13h1v1H2zm11 0h1v1h-1zM3 14h2v1H3zm8 0h2v1h-2zM5 15h6v1H5zM4 5h2v2H4zm6 0h2v2h-2zM4 9h2v2h4V9h2v2h-1v1H5v-1H4z",
  neutral:
    "M5 0h6v1H5zM3 1h2v1H3zm8 0h2v1h-2zM2 2h1v1H2zm11 0h1v1h-1zM1 3h1v2H1zm13 0h1v2h-1zM0 5h1v6H0zm15 0h1v6h-1zM1 11h1v2H1zm13 0h1v2h-1zM2 13h1v1H2zm11 0h1v1h-1zM3 14h2v1H3zm8 0h2v1h-2zM5 15h6v1H5zM4 5h2v2H4zm6 0h2v2h-2zM4 10h8v1H4z",
  unhappy:
    "M5 0h6v1H5zM3 1h2v1H3zm8 0h2v1h-2zM2 2h1v1H2zm11 0h1v1h-1zM1 3h1v2H1zm13 0h1v2h-1zM0 5h1v6H0zm15 0h1v6h-1zM1 11h1v2H1zm13 0h1v2h-1zM2 13h1v1H2zm11 0h1v1h-1zM3 14h2v1H3zm8 0h2v1h-2zM5 15h6v1H5zM4 5h2v2H4zm6 0h2v2h-2zM5 9h6v1h1v2h-2v-2H6v2H4v-2h1z",
  home: "M7 1h2v1h1v1h1v1h1v1h1v1h1v1h1v2h-2v6H9v-5H7v5H3V9H1V7h1V6h1V5h1V4h1V3h1V2h1V1z",
  hourglass:
    "M3 1h10v2h-1v3h-1v1H9v2h2v1h1v3h1v2H3v-2h1v-3h1V9h2V7H5V6H4V3H3V1zm2 2v2h1v1h4V5h1V3H5zm2 7v1H6v1H5v1h6v-1h-1v-1H9v-1H7z",
  trash:
    "M5 1h6v2h3v2H2V3h3V1zm1 1v1h4V2H6zM3 6h10v9H3V6zm2 1v6h1V7H5zm3 0v6h1V7H8zm3 0v6h1V7h-1z",
  copy: "M1 1h9v3h4v11H5v-3H1V1zm1 1v9h3V4h4V2H2zm4 3v9h7V5H6z",
  download: "M7 1h2v7h3l-4 4-4-4h3V1zM2 11h2v3h8v-3h2v5H2v-5z",
  file: "M3 1h7v1h1v1h1v1h1v11H3V1zm1 1v12h8V5H9V2H4zm1 5h6v1H5V7zm0 3h6v1H5v-1z",
  overview:
    "M1 2h14v10H9v2h3v1H4v-1h3v-2H1V2zm1 1v8h12V3H2zm2 5h2v2H4V8zm3-2h2v4H7V6zm3-2h2v6h-2V4z",
  risk: "M2 1h12v1h1v7h-1v2h-2v2h-2v1H9v1H7v-1H6v-1H4v-2H2V9H1V2h1V1zm1 2v6h1v2h2v1h1v1h2v-1h1v-1h2V9h1V3H3zm4 1h2v5H7V4zm0 6h2v2H7v-2z",
  sections:
    "M1 2h14v12H1V2zm1 1v3h5V3H2zm6 0v3h6V3H8zM2 7v6h5V7H2zm6 0v6h6V7H8z",
  signature:
    "M2 1h9v5h-1V2H3v12h7v-3h1v4H2V1zm3 3h3v1H5V4zm0 3h3v1H5V7zm3 2h2v2h1V9h1V7h2v3h-1v2h-1v2h-2v-1H9v-2H8V9z",
  warning:
    "M7 1h2v2h1v2h1v2h1v2h1v2h1v2h1v2H1v-2h1v-2h1V9h1V7h1V5h1V3h1V1zm0 4v5h2V5H7zm0 7v2h2v-2H7z",
  imports: "M1 2h6v2h8v10H1V2zm1 3v8h12V5H2zm5 1h2v3h2l-3 3-3-3h2V6z",
  maximize: "M2 2h12v12H2V2zm1 3v8h10V5H3z",
  restore: "M5 1h10v10h-3v4H1V5h4V1zm1 3v1h6v5h2V4H6zM2 8v6h9V8H2z",
  close:
    "M3 2h2v2h2v2h2V4h2V2h2v3h-2v2H9v2h2v2h2v3h-2v-2H9v-2H7v2H5v2H3v-3h2V9h2V7H5V5H3V2z",
};

export default function RetroIcon({
  name,
  size = 16,
}: {
  name: RetroIconName;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      focusable="false"
      className="retro-icon"
      shapeRendering="crispEdges"
    >
      <path fill="currentColor" d={paths[name]} />
    </svg>
  );
}
