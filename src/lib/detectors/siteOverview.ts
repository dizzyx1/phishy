/**
 * Site Overview & Web Intelligence Analyzer
 *
 * Gathers a concise description/bio of the target website using web intelligence,
 * search endpoints, OpenGraph/meta descriptions, and DuckDuckGo abstracts.
 */

import axios from "axios";
import * as cheerio from "cheerio";

export interface SiteOverview {
  title: string | null;
  description: string | null;
  category: string | null;
  source: string;
}

export async function getSiteOverview(
  urlString: string,
  hostname: string
): Promise<SiteOverview | null> {
  const cleanDomain = hostname.replace(/^www\./i, "");
  const brandName = cleanDomain.split(".")[0];

  // 1. Try DuckDuckGo Instant Answer API for known sites/brands
  try {
    const ddgRes = await axios.get(
      `https://api.duckduckgo.com/?q=${encodeURIComponent(cleanDomain)}&format=json&no_redirect=1&no_html=1`,
      { timeout: 3500 }
    );
    if (ddgRes.data && (ddgRes.data.AbstractText || ddgRes.data.Heading)) {
      const desc = ddgRes.data.AbstractText || ddgRes.data.Heading;
      return {
        title: ddgRes.data.Heading || cleanDomain,
        description: desc,
        category: ddgRes.data.Entity || "Web Entity",
        source: "DuckDuckGo Knowledge Base",
      };
    }
  } catch {
    // Fall back to page content inspection
  }

  // 2. Fetch the target homepage HTML to extract title, OpenGraph description, and meta tags
  try {
    const pageRes = await axios.get(urlString, {
      timeout: 4500,
      maxRedirects: 3,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    if (typeof pageRes.data === "string") {
      const $ = cheerio.load(pageRes.data);
      const title =
        $('meta[property="og:title"]').attr("content") ||
        $("title").text().trim() ||
        null;
      let description =
        $('meta[property="og:description"]').attr("content") ||
        $('meta[name="description"]').attr("content") ||
        $('meta[name="twitter:description"]').attr("content") ||
        null;

      if (description) {
        description = description.replace(/\s+/g, " ").trim();
      }

      // If we found a description from the page
      if (description && description.length > 10) {
        let guessedCategory = "General Website";
        const lowerDesc = (description + " " + (title || "")).toLowerCase();
        if (
          lowerDesc.includes("stream") ||
          lowerDesc.includes("movie") ||
          lowerDesc.includes("watch online") ||
          lowerDesc.includes("cinema") ||
          lowerDesc.includes("anime")
        ) {
          guessedCategory = "Streaming / Entertainment";
        } else if (
          lowerDesc.includes("bank") ||
          lowerDesc.includes("finance") ||
          lowerDesc.includes("payment") ||
          lowerDesc.includes("crypto") ||
          lowerDesc.includes("wallet")
        ) {
          guessedCategory = "Financial Services / Banking";
        } else if (
          lowerDesc.includes("shop") ||
          lowerDesc.includes("store") ||
          lowerDesc.includes("ecommerce") ||
          lowerDesc.includes("cart")
        ) {
          guessedCategory = "E-Commerce / Shopping";
        } else if (
          lowerDesc.includes("login") ||
          lowerDesc.includes("portal") ||
          lowerDesc.includes("verify")
        ) {
          guessedCategory = "Authentication Portal";
        } else if (
          lowerDesc.includes("software") ||
          lowerDesc.includes("github") ||
          lowerDesc.includes("code") ||
          lowerDesc.includes("developer")
        ) {
          guessedCategory = "Technology / Developer Platform";
        }

        return {
          title: title || cleanDomain,
          description,
          category: guessedCategory,
          source: "Live Web Metadata & Content Analysis",
        };
      }

      // If no description tag was present, try reading the first descriptive paragraph
      const firstParagraph = $("main p, article p, p")
        .filter((_, el) => $(el).text().trim().length > 30)
        .first()
        .text()
        .trim();

      if (firstParagraph && firstParagraph.length > 20) {
        return {
          title: title || cleanDomain,
          description:
            firstParagraph.length > 250
              ? firstParagraph.slice(0, 247) + "..."
              : firstParagraph,
          category: "Web Resource",
          source: "Direct Page Heuristics",
        };
      }
    }
  } catch {
    // If site unreachable, fallback
  }

  // 3. Fallback heuristic summary for common domains / patterns
  return {
    title: cleanDomain,
    description: `Online domain registered under .${cleanDomain.split(".").pop()} namespace. No public description or search indexing available.`,
    category: "Uncategorized Domain",
    source: "Domain Heuristics",
  };
}
