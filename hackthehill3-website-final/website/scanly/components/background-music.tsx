"use client";

import { useEffect, useRef } from "react";
import {
  readSettings,
  SETTINGS_EVENT,
  SETTINGS_KEY,
  SoundSettings,
} from "@/lib/retro-sounds";

export default function BackgroundMusic() {
  const audioRef = useRef<HTMLAudioElement>(null);
  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;
    let settings = readSettings();
    let disposed = false;
    function play() {
      if (!audio || disposed || !settings.music || settings.musicVolume === 0)
        return;
      if (audio.paused) {
        void audio
          .play()
          .then(() => {
            if (disposed || !settings.music || settings.musicVolume === 0)
              audio.pause();
          })
          .catch(() => {
            /* Retry on the next interaction if autoplay is blocked. */
          });
      }
    }
    function apply(next: SoundSettings) {
      settings = next;
      audio!.volume = next.musicVolume;
      if (!next.music || next.musicVolume === 0) audio!.pause();
      else play();
    }
    function changed(event: Event) {
      apply((event as CustomEvent<SoundSettings>).detail);
    }
    function storage(event: StorageEvent) {
      if (event.key === SETTINGS_KEY || event.key === null)
        apply(readSettings());
    }
    apply(settings);
    document.addEventListener("click", play);
    document.addEventListener("keydown", play);
    window.addEventListener(SETTINGS_EVENT, changed);
    window.addEventListener("storage", storage);
    return () => {
      disposed = true;
      audio.pause();
      document.removeEventListener("click", play);
      document.removeEventListener("keydown", play);
      window.removeEventListener(SETTINGS_EVENT, changed);
      window.removeEventListener("storage", storage);
    };
  }, []);
  return (
    <audio
      ref={audioRef}
      src="/audio/background-music.mp3"
      loop
      preload="auto"
      aria-hidden="true"
    />
  );
}
