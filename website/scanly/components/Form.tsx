import React from "react"

export default function Form({ children }: { children?: React.ReactNode }) {
    return (
        <section className="retro-panel mt-6 w-full">
            <div className="mb-4">
                <h1 className="retro-heading">New scan</h1>
                <p className="mt-1 text-xs text-[#805775]">Choose your folders, then click Scan All.</p>
            </div>
            <div className="grid items-end gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">{children}</div>

        </section>
    )
}
