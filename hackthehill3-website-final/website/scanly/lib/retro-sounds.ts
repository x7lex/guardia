export const SETTINGS_KEY = 'gaurdia.settings.v1'
export const SETTINGS_EVENT = "gaurdia-settings-change"
export type SoundSettings = { sounds: boolean; volume: number; music: boolean; musicVolume: number }
export const DEFAULT_SETTINGS: SoundSettings = { sounds: false, volume: 0.25, music: true, musicVolume: 0.3 }
let context: AudioContext | null = null
export function readSettings(): SoundSettings {
    try {
        const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? 'null')
        return { music: saved?.music !== false, musicVolume: typeof saved?.musicVolume === "number" && Number.isFinite(saved.musicVolume) ? Math.max(0, Math.min(1, saved.musicVolume)) : DEFAULT_SETTINGS.musicVolume, sounds: saved?.sounds === true, volume: typeof saved?.volume === 'number' && Number.isFinite(saved.volume) ? Math.max(0, Math.min(1, saved.volume)) : DEFAULT_SETTINGS.volume }
    } catch { return DEFAULT_SETTINGS }
}
export async function playRetroSound(kind: 'click' | 'complete', settings = readSettings()) {
    if (!settings.sounds || !settings.volume) return
    try {
        context ??= new AudioContext()
        await context.resume()
        const start = context.currentTime
        const notes = kind === 'complete' ? [523.25, 659.25, 783.99] : [880]
        notes.forEach((frequency, index) => {
            const oscillator = context!.createOscillator()
            const gain = context!.createGain()
            oscillator.type = 'square'
            oscillator.frequency.value = frequency
            const when = start + index * 0.11
            gain.gain.setValueAtTime(settings.volume * 0.06, when)
            gain.gain.exponentialRampToValueAtTime(0.0001, when + 0.09)
            oscillator.connect(gain); gain.connect(context!.destination)
            oscillator.start(when); oscillator.stop(when + 0.1)
            oscillator.onended = () => { oscillator.disconnect(); gain.disconnect() }
        })
    } catch { /* Browsers may block sound until the next user interaction. */ }
}
