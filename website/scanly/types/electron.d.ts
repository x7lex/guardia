export {}

declare global {
    interface Window {
        electronAPI?: {
            selectFolders: () => Promise<string[]>
            getPathForFile: (file: File) => string
        }
    }
}
