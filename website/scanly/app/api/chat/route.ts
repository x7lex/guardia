export const runtime = "nodejs"

export async function POST(request: Request) {
    try {
        const options: RequestInit & { duplex: "half" } = {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: request.body, duplex: "half", signal: request.signal, cache: "no-store",
        }
        const response = await fetch(new URL("/chat", process.env.BACKEND_URL || "http://127.0.0.1:8000"), options)
        return new Response(response.body, { status: response.status,
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } })
    } catch {
        return Response.json({ detail: "Gemini chat could not connect. Please try again." }, { status: 502 })
    }
}
