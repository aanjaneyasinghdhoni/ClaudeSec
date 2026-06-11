import { lazy, type ComponentType, type LazyExoticComponent } from 'react';
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
  /**
   * Stable lazy component, created once per page. Creating React.lazy during
   * render breaks under startTransition-based navigation: a suspended
   * transition never commits, so a per-render lazy gets recreated on every
   * retry and the navigation never finishes (URL moves, content doesn't).
   */
  Component: LazyExoticComponent<ComponentType>;
}

export interface DocNavGroup {
  group: string;
  pages: DocPage[];
}

export interface DocSearchEntry {
  slug: string;
  title: string;
  description: string;
  headings: string[];
  text: string;
}

const frontmatters = import.meta.glob<DocFrontmatter>(
  ['/docs/**/*.mdx', '!/docs/_local/**'],
  { eager: true, import: 'frontmatter' },
);

const loaders = import.meta.glob(['/docs/**/*.mdx', '!/docs/_local/**']);

const rawSources = import.meta.glob<string>(
  ['/docs/**/*.mdx', '!/docs/_local/**'],
  { eager: true, query: '?raw', import: 'default' },
);

function toSlug(filePath: string): string {
  return filePath.replace(/^\/docs\//, '').replace(/\.mdx$/, '');
}

function humanize(slug: string): string {
  const last = slug.split('/').pop() ?? slug;
  return last.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// A docs chunk can vanish from under an open tab: the on-disk build gets
// replaced (new content hashes) while the browser still runs the old
// index.html, so the dynamic import 404s and clicking a doc changes the URL
// but not the page. Recover by reloading once to pick up the fresh build;
// the sessionStorage guard prevents a reload loop when the failure has some
// other cause, and is cleared again by the next successful load.
const STALE_CHUNK_KEY = 'claudesec.docs.staleChunkReloaded';
function recoveringLoader(load: DocPage['load']): DocPage['load'] {
  return () =>
    load()
      .then(mod => {
        try { sessionStorage.removeItem(STALE_CHUNK_KEY); } catch { /* ignore */ }
        return mod;
      })
      .catch(err => {
        let alreadyReloaded = true;
        try {
          alreadyReloaded = sessionStorage.getItem(STALE_CHUNK_KEY) !== null;
          if (!alreadyReloaded) sessionStorage.setItem(STALE_CHUNK_KEY, '1');
        } catch { /* ignore */ }
        if (!alreadyReloaded) window.location.reload();
        throw err;
      });
}

const pages: Record<string, DocPage> = {};
for (const [filePath, loader] of Object.entries(loaders)) {
  const slug = toSlug(filePath);
  const fm = (frontmatters[filePath] ?? {}) as DocFrontmatter;
  const load = recoveringLoader(loader as DocPage['load']);
  pages[slug] = {
    slug,
    title: fm.title || humanize(slug),
    description: fm.description ?? '',
    load,
    Component: lazy(load),
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

export interface DocOrderEntry {
  slug: string;
  title: string;
}

export const docsOrder: DocOrderEntry[] = navGroups.flatMap(g =>
  g.pages.map(p => ({ slug: p.slug, title: p.title })),
);
export const defaultDocSlug =
  navGroups[0]?.pages[0]?.slug ?? Object.keys(pages)[0] ?? '';

export function getDocPage(slug: string): DocPage | undefined {
  return pages[slug];
}

export function slugifyHeading(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function stripFrontmatter(raw: string): string {
  return raw.replace(/^﻿?---\r?\n[\s\S]*?\r?\n---\r?\n?/, '');
}

function extractHeadings(body: string): string[] {
  const out: string[] = [];
  const re = /^#{1,3}\s+(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const h = m[1].replace(/[#*`_]/g, '').trim();
    if (h) out.push(h);
  }
  return out;
}

function toPlainText(body: string): string {
  return body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]*`/g, ' ')
    .replace(/<\/?[A-Za-z][^>]*>/g, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/[*_~>#|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 2000);
}

const searchEntries: DocSearchEntry[] = [];
for (const [filePath, raw] of Object.entries(rawSources)) {
  const slug = toSlug(filePath);
  const page = pages[slug];
  const body = stripFrontmatter(typeof raw === 'string' ? raw : '');
  searchEntries.push({
    slug,
    title: page?.title ?? humanize(slug),
    description: page?.description ?? '',
    headings: extractHeadings(body),
    text: toPlainText(body),
  });
}

export const docsSearchIndex: DocSearchEntry[] = searchEntries;
