/// <reference types="vite/client" />

declare module '*.mdx' {
  import type { ComponentType } from 'react';
  export const frontmatter: { title?: string; description?: string; icon?: string };
  const MDXComponent: ComponentType<Record<string, unknown>>;
  export default MDXComponent;
}
