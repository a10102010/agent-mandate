/**
 * NonceRegistry: replay protection.
 * Interface + InMemory default implementation.
 */

export interface NonceRegistry {
  has(hash: string): boolean;
  add(hash: string): void;
}

export class InMemoryNonceRegistry implements NonceRegistry {
  private readonly seen = new Set<string>();

  has(hash: string): boolean {
    return this.seen.has(hash);
  }

  add(hash: string): void {
    this.seen.add(hash);
  }
}
