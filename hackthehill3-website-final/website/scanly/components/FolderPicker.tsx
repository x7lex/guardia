"use client";

import { useRef } from "react";

export default function FolderPicker({
  onFilesSelected,
  disabled = false,
}: {
  onFilesSelected: (files: File[]) => void;
  disabled?: boolean;
}) {
  const folderInput = useRef<HTMLInputElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  function select(input: HTMLInputElement) {
    const files = Array.from(input.files ?? []);
    if (files.length) onFilesSelected(files);
    input.value = "";
  }
  return (
    <div className="flex w-full flex-wrap gap-2">
      <input
        ref={folderInput}
        type="file"
        multiple
        {...{ webkitdirectory: "" }}
        aria-label="Choose folder"
        className="sr-only"
        tabIndex={-1}
        disabled={disabled}
        onChange={(event) => select(event.currentTarget)}
      />
      <input
        ref={fileInput}
        type="file"
        multiple
        aria-label="Choose files"
        className="sr-only"
        tabIndex={-1}
        disabled={disabled}
        onChange={(event) => select(event.currentTarget)}
      />
      <button
        type="button"
        disabled={disabled}
        onClick={() => folderInput.current?.click()}
        className="retro-button px-4"
      >
        Browse folder…
      </button>
      <button
        type="button"
        disabled={disabled}
        onClick={() => fileInput.current?.click()}
        className="retro-button px-4"
      >
        Choose files…
      </button>
    </div>
  );
}
