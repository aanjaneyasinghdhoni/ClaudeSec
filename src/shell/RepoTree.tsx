import React, { useCallback, useMemo, useState } from 'react';
import { ChevronRight, Folder, FolderGit2, HelpCircle, Star } from 'lucide-react';
import { UNKNOWN_REPO, repoLabel, type Repo } from '../dashboardTypes';
import {
  SidebarGroup, SidebarGroupContent, SidebarGroupLabel,
  SidebarMenu, SidebarMenuItem, SidebarMenuSub, SidebarMenuSubItem,
} from '../components/ui/sidebar';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible';
import { buildTree, type TreeNode } from './repoTreeGrouping';

const PINNED_KEY = 'claudesec.pinnedRepos';

export interface RepoTreeProps {
  repos: Repo[];
  /** Repo keys currently filtering the view — the same `?repo=` the bar reads. */
  selected: string[];
  onToggle: (repo: string) => void;
}

export function RepoTree({ repos, selected, onToggle }: RepoTreeProps) {
  const [pinned, setPinned] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(PINNED_KEY) ?? '[]') as string[]; }
    catch { return []; }
  });

  const togglePin = useCallback((key: string) => {
    setPinned(prev => {
      const next = prev.includes(key) ? prev.filter(p => p !== key) : [...prev, key];
      try { localStorage.setItem(PINNED_KEY, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  }, []);

  const tree = useMemo(() => buildTree(repos), [repos]);

  // Shortcuts sit above the tree — this is the pattern that actually scales a
  // long nav: the handful you keep coming back to are one click away, and the
  // rest stay one expand away. With nothing pinned yet, the repos that have
  // high-severity findings stand in, so the block is never empty and useless.
  const shortcuts = useMemo(() => {
    const explicit = repos.filter(r => pinned.includes(r.repo));
    if (explicit.length > 0) return explicit;
    return repos.filter(r => r.threatHigh > 0).slice(0, 4);
  }, [repos, pinned]);

  if (repos.length === 0) return null;

  return (
    <>
      {shortcuts.length > 0 && (
        <SidebarGroup className="p-1.5">
          <SidebarGroupLabel className="h-6 text-[10px] font-semibold uppercase tracking-wider">
            {pinned.length > 0 ? 'Shortcuts' : 'Needs attention'}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {shortcuts.map(repo => (
                <SidebarMenuItem key={repo.repo}>
                  <RepoRow
                    repo={repo}
                    depth={0}
                    selected={selected.includes(repo.repo)}
                    pinned={pinned.includes(repo.repo)}
                    onToggle={onToggle}
                    onTogglePin={togglePin}
                  />
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      )}

      <SidebarGroup className="p-1.5">
        <SidebarGroupLabel className="h-6 text-[10px] font-semibold uppercase tracking-wider">
          <FolderGit2 className="mr-1.5 size-3" /> Repositories
          <span className="ml-auto font-mono tabular-nums">{repos.length}</span>
        </SidebarGroupLabel>
        <SidebarGroupContent>
          <SidebarMenu>
            {tree.map(node => (
              <SidebarMenuItem key={node.name}>
                <TreeBranch node={node} depth={0} selected={selected} pinned={pinned} onToggle={onToggle} onTogglePin={togglePin} />
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>
    </>
  );
}

function TreeBranch({ node, depth, selected, pinned, onToggle, onTogglePin }: {
  node: TreeNode;
  depth: number;
  selected: string[];
  pinned: string[];
  onToggle: (repo: string) => void;
  onTogglePin: (repo: string) => void;
}) {
  const [open, setOpen] = useState(depth === 0 && node.children.length > 0 && node.children.length <= 8);

  if (node.children.length === 0) {
    if (!node.repo) return null;
    return (
      <RepoRow
        repo={node.repo}
        depth={depth}
        selected={selected.includes(node.repo.repo)}
        pinned={pinned.includes(node.repo.repo)}
        onToggle={onToggle}
        onTogglePin={onTogglePin}
      />
    );
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className="flex h-7 w-full items-center gap-1.5 rounded-md pr-2 text-left text-xs transition-colors hover:bg-sidebar-accent"
        style={{ paddingLeft: `${0.25 + depth * 0.6}rem`, color: 'var(--cs-text-muted)' }}
      >
        <ChevronRight className={`size-3 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`} />
        <Folder className="size-3 shrink-0 opacity-60" />
        <span className="truncate">{node.name}</span>
        <span className="ml-auto font-mono text-[10px] tabular-nums" style={{ color: 'var(--cs-text-faint)' }}>
          {countRepos(node)}
        </span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <SidebarMenuSub className="mx-0 border-0 px-0">
          {node.repo && (
            <SidebarMenuSubItem>
              <RepoRow
                repo={node.repo}
                depth={depth + 1}
                selected={selected.includes(node.repo.repo)}
                pinned={pinned.includes(node.repo.repo)}
                onToggle={onToggle}
                onTogglePin={onTogglePin}
              />
            </SidebarMenuSubItem>
          )}
          {node.children.map(child => (
            <SidebarMenuSubItem key={child.name}>
              <TreeBranch node={child} depth={depth + 1} selected={selected} pinned={pinned} onToggle={onToggle} onTogglePin={onTogglePin} />
            </SidebarMenuSubItem>
          ))}
        </SidebarMenuSub>
      </CollapsibleContent>
    </Collapsible>
  );
}

function countRepos(node: TreeNode): number {
  return (node.repo ? 1 : 0) + node.children.reduce((sum, c) => sum + countRepos(c), 0);
}

function RepoRow({ repo, depth, selected, pinned, onToggle, onTogglePin }: {
  repo: Repo;
  depth: number;
  selected: boolean;
  pinned: boolean;
  onToggle: (repo: string) => void;
  onTogglePin: (repo: string) => void;
}) {
  const unknown = repo.repo === UNKNOWN_REPO;
  return (
    <div className="group/repo flex h-7 items-center gap-1.5 rounded-md pr-1 transition-colors hover:bg-sidebar-accent"
      style={{ paddingLeft: `${0.25 + depth * 0.6}rem`, background: selected ? 'var(--cs-accent-soft)' : undefined }}
    >
      <span
        className="h-4 w-[3px] shrink-0 rounded-full"
        style={{ background: repo.threatHigh > 0 ? 'var(--cs-sev-critical)' : 'var(--cs-sev-none)' }}
      />
      <button
        type="button"
        onClick={() => onToggle(repo.repo)}
        aria-pressed={selected}
        title={unknown
          ? 'Activity captured before repository tracking, or from agents that don’t report a working directory.'
          : repo.repo}
        className="flex min-w-0 flex-1 items-center gap-1 text-left text-xs"
        style={{ color: selected ? 'var(--cs-accent)' : 'var(--cs-text-body)' }}
      >
        {unknown && <HelpCircle className="size-3 shrink-0 opacity-60" />}
        <span className="truncate">{repoLabel(repo.repo)}</span>
      </button>
      {repo.threatHigh > 0 && (
        <span className="shrink-0 font-mono text-[10px] tabular-nums" style={{ color: 'var(--cs-sev-critical-fg)' }}>
          {repo.threatHigh}
        </span>
      )}
      <button
        type="button"
        onClick={() => onTogglePin(repo.repo)}
        aria-label={pinned ? `Unpin ${repoLabel(repo.repo)}` : `Pin ${repoLabel(repo.repo)}`}
        className={`shrink-0 rounded p-0.5 transition-opacity ${pinned ? 'opacity-70' : 'opacity-0 group-hover/repo:opacity-100 focus-visible:opacity-100'}`}
        style={{ color: pinned ? 'var(--cs-sev-medium)' : 'var(--cs-text-faint)' }}
      >
        <Star className="size-3" fill={pinned ? 'currentColor' : 'none'} />
      </button>
    </div>
  );
}
