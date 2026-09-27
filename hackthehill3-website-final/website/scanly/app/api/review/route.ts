export const runtime = "nodejs";

export async function POST(request: Request) {
  if (process.env.GUARDIA_DESKTOP_TOKEN &&
      request.headers.get("x-guardia-token") !== process.env.GUARDIA_DESKTOP_TOKEN) {
    return Response.json({ detail: "Unauthorized" }, { status: 401 });
  }
  try {
    const backend = new URL(
      "/review",
      process.env.BACKEND_URL || "http://127.0.0.1:8000",
    );
    const options: RequestInit & { duplex: "half" } = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(process.env.GUARDIA_DESKTOP_TOKEN
          ? { "x-guardia-token": process.env.GUARDIA_DESKTOP_TOKEN }
          : {}),
      },
      body: request.body,
      duplex: "half",
      signal: request.signal,
      cache: "no-store",
    };
    const response = await fetch(backend, options);
    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return Response.json(
      {
        detail:
          "Review service unavailable. Start the Python backend and try again.",
      },
      { status: 502 },
    );
  }
}
