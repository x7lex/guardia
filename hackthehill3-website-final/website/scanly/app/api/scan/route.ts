export const runtime = "nodejs"

export async function POST(request: Request) {
    const name = new URL(request.url).searchParams.get("name")
    if (!name) return Response.json({ detail: "Choose a file to scan" }, { status: 400 })
    const backend = new URL("/scan", process.env.BACKEND_URL || "http://127.0.0.1:8000")
    backend.searchParams.set("name", name)
    const headers = new Headers({ "Content-Type": request.headers.get("content-type") || "application/octet-stream" })
    const length = request.headers.get("content-length")
    if (length) headers.set("Content-Length", length)
    try {
        // Stream uploads to Python instead of buffering executable files in Node.
        const options: RequestInit & { duplex: "half" } = {
            method: "POST", headers, body: request.body, duplex: "half",
            signal: request.signal, cache: "no-store",
        }
        const response = await fetch(backend, options)
        return new Response(response.body, { status: response.status,
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } })
    } catch {
        return Response.json({ detail: "Scanner unavailable. Start the Python backend and try again." }, { status: 502 })
    }
}
