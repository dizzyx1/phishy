import { NextRequest, NextResponse } from "next/server";
import { scanUrl } from "@/lib/scanner";

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
    return NextResponse.json(
      { error: "Failed to complete URL scan. Please check the input and try again." },
      { status: 500 }
    );
  }
}
