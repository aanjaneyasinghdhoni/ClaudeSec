import type { ComponentType } from 'react';
import docsJson from '@/docs/docs.json';

export interface DocFrontmatter {
  title?: string;
  description?: string;
  icon?: string;
}

export interface DocPage {
  slug: string;
  title: string;
  description: string;
  load: () => Promise<{ default: ComponentType }>;
}

export interface DocNavGroup {
  group: string;
  pages: DocPage[];
}

const frontmatters = import.meta.glob<DocFrontmatter>(
  ['/docs/**/*.mdx', '!/docs/superpowers/**'],
  { eager: true, import: 'frontmatter' },
);

const loaders = import.meta.glob(['/docs/**/*.mdx', '!/docs/superpowers/**']);

function toSlug(filePath: string): string {
  return filePath.replace(/^\/docs\//, '').replace(/\.mdx$/, '');
}

function humanize(slug: string): string {
  const last = slug.split('/').pop() ?? slug;
  return last.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

const pages: Record<string, DocPage> = {};
for (const [filePath, loader] of Object.entries(loaders)) {
  const slug = toSlug(filePath);
  const fm = (frontmatters[filePath] ?? {}) as DocFrontmatter;
  pages[slug] = {
    slug,
    title: fm.title || humanize(slug),
    description: fm.description ?? '',
    load: loader as DocPage['load'],
  };
}

interface RawGroup { group: string; pages: unknown[]; }
const rawGroups =
  (docsJson as { navigation?: { groups?: RawGroup[] } }).navigation?.groups ?? [];

const navGroups: DocNavGroup[] = [];
const claimed = new Set<string>();

for (const g of rawGroups) {
  const groupPages: DocPage[] = [];
  for (const entry of g.pages ?? []) {
    if (typeof entry !== 'string') continue;
    const page = pages[entry];
    if (page) {
      groupPages.push(page);
      claimed.add(entry);
    }
  }
  if (groupPages.length) navGroups.push({ group: g.group, pages: groupPages });
}

const orphans = Object.values(pages).filter(p => !claimed.has(p.slug));
if (orphans.length) {
  navGroups.push({
    group: 'Other',
    pages: orphans.sort((a, b) => a.slug.localeCompare(b.slug)),
  });
}

export const docsNav = navGroups;
export const docsPages = pages;
export const defaultDocSlug =
  navGroups[0]?.pages[0]?.slug ?? Object.keys(pages)[0] ?? '';

export function getDocPage(slug: string): DocPage | undefined {
  return pages[slug];
}
