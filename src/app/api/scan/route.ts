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

    const result = await scanUrl(url);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error("Scan error:", error);
    return NextResponse.json(
      { error: "Failed to complete URL scan. Please check the input and try again." },
      { status: 500 }
    );
  }
}
