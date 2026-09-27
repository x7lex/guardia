"use client";

import { useEffect, useRef, useState } from "react";
import RetroIcon from "@/components/retro-icon";
import {
  DEFAULT_SETTINGS,
  SETTINGS_KEY,
  SETTINGS_EVENT,
  SoundSettings,
  readSettings,
  playRetroSound,
} from "@/lib/retro-sounds";

export default function Settings() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [notice, setNotice] = useState("");
  const detailsRef = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    // Restore browser preferences after hydration without overwriting saved values.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSettings(readSettings());
  }, []);
  function update(next: SoundSettings) {
    setSettings(next);
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
      setNotice("Saved on this device.");
    } catch {
      setNotice(
        "Device storage is unavailable; preferences could not be saved.",
      );
    }
    window.dispatchEvent(new CustomEvent(SETTINGS_EVENT, { detail: next }));
  }
  return (
    <details ref={detailsRef} className="relative text-[#70535f]">
      <summary className="retro-button flex min-h-10 items-center gap-2 px-4">
        <RetroIcon name="gear" />
        Settings
      </summary>
      <section
        className="retro-settings absolute right-0 top-full z-50 mt-2 w-72 max-w-[90vw]"
        aria-label="Sound settings"
      >
        <div className="retro-window-title">
          <span className="inline-flex items-center gap-2">
            <RetroIcon name="gear" />
            Sound control
          </span>
          <button
            type="button"
            className="retro-window-control"
            aria-label="Close settings"
            onClick={() => {
              if (detailsRef.current) detailsRef.current.open = false;
            }}
          >
            <RetroIcon name="close" size={12} />
          </button>
        </div>
        <div className="max-h-[65vh] overflow-y-auto p-3">
          <fieldset className="retro-settings-group">
            <legend>Background music</legend>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="retro-speaker-toggle"
                aria-label={
                  settings.music
                    ? "Mute background music"
                    : "Unmute background music"
                }
                title={settings.music ? "Mute music" : "Unmute music"}
                aria-pressed={settings.music}
                onClick={() => update({ ...settings, music: !settings.music })}
              >
                <RetroIcon
                  name={settings.music ? "speaker" : "muted"}
                  size={28}
                />
              </button>
              <span className="text-xs">
                {settings.music ? "Music on" : "Music muted"}
              </span>
            </div>
            <label className="mt-3 block text-xs">
              Music volume · {Math.round(settings.musicVolume * 100)}%
              <input
                className="retro-slider mt-2 w-full"
                type="range"
                min="0"
                max="100"
                value={Math.round(settings.musicVolume * 100)}
                onChange={(event) =>
                  update({
                    ...settings,
                    musicVolume: Number(event.target.value) / 100,
                  })
                }
              />
            </label>
          </fieldset>
          <fieldset className="retro-settings-group mt-4">
            <legend>Sound effects</legend>
            <label className="flex items-center gap-2 text-xs">
              <input
                className="retro-checkbox"
                type="checkbox"
                checked={settings.sounds}
                onChange={(event) => {
                  const next = { ...settings, sounds: event.target.checked };
                  update(next);
                  void playRetroSound("click", next);
                }}
              />
              Enable clicks and chimes
            </label>
            <label className="mt-3 block text-xs">
              Effects volume · {Math.round(settings.volume * 100)}%
              <input
                className="retro-slider mt-2 w-full"
                type="range"
                min="0"
                max="100"
                value={Math.round(settings.volume * 100)}
                onChange={(event) =>
                  update({
                    ...settings,
                    volume: Number(event.target.value) / 100,
                  })
                }
              />
            </label>
            <button
              className="retro-button mt-3 px-3"
              disabled={!settings.sounds}
              onClick={() => void playRetroSound("complete", settings)}
            >
              Test sound
            </button>
          </fieldset>
          <p role="status" className="retro-settings-status mt-3 text-xs">
            {notice || "Preferences saved on this device."}
          </p>
        </div>
      </section>
    </details>
  );
}
