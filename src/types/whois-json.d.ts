declare module "whois-json" {
  export function lookupAsync(
    domain: string,
    options?: { timeout?: number; follow?: number; server?: string }
  ): Promise<Record<string, any>>;
}
