import { NextRequest, NextResponse } from "next/server";
import { scanUrl } from "@/lib/scanner";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json(
        { error: "A valid URL string is required." },
        { status: 400 }
      );
    }

    if (url.trim().length > 2048) {
      return NextResponse.json(
        { error: "URL exceeds the maximum allowed length of 2048 characters." },
        { status: 400 }
      );
    }

    const result = await scanUrl(url);
    return NextResponse.json(result);
  } catch (error) {
    console.error("Scan error:", error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    return NextResponse.json(
      {
        error: "Failed to complete URL scan. Please check the input and try again.",
        details: errorMessage,
        stack: process.env.NODE_ENV === "development" ? errorStack : undefined,
      },
      { status: 500 }
    );
  }
}
