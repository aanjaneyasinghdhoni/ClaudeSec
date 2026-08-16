import React from 'react';
import { BookOpen, PanelLeftClose, PanelLeftOpen, Shield } from 'lucide-react';
import { CATEGORIES, type Category } from '../CategoryNav';
import { CATEGORY_TABS, type Tab } from '../dashboardTypes';
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent,
  SidebarHeader, SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem,
  useSidebar,
} from '../components/ui/sidebar';

export interface NavRailProps {
  activeCategory: Category;
  activeTab: Tab;
  docsActive: boolean;
  alertCount: number;
  onCategoryChange: (category: Category) => void;
  onTabChange: (tab: Tab) => void;
  onOpenDocs: () => void;
}

/**
 * Zone one: the icon rail. Five groups, nothing else — this navigates and never
 * filters, which is the rule that lets the filter bar be the only filter.
 *
 * Collapsed it is a 3rem strip of icons; the tooltip prop on SidebarMenuButton
 * renders only in that state, so the flyout labels come for free and there is no
 * second "collapsed" markup path to keep in sync. Expanded it shows the label
 * plus the tabs inside the active category, so every view is reachable in one
 * click without hunting through categories.
 */
export function NavRail({
  activeCategory, activeTab, docsActive, alertCount,
  onCategoryChange, onTabChange, onOpenDocs,
}: NavRailProps) {
  const { state, toggleSidebar, isMobile } = useSidebar();
  const collapsed = state === 'collapsed' && !isMobile;

  return (
    <Sidebar
      collapsible="none"
      className="w-12 shrink-0 transition-[width] duration-200 ease-out lg:w-(--cs-rail-w) lg:group-data-[collapsible=icon]:w-12 motion-reduce:transition-none"
      style={{ borderRight: '1px solid var(--cs-rule)' }}
    >
      <SidebarHeader className="p-1.5">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              onClick={toggleSidebar}
              tooltip="Expand navigation (⌘B)"
              className="text-[13px]"
            >
              {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
              <span className="max-lg:hidden">Collapse</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup className="p-1.5">
          <SidebarGroupContent>
            <SidebarMenu className="gap-0.5">
              {CATEGORIES.map(category => {
                const isActive = !docsActive && activeCategory === category.id;
                return (
                  <SidebarMenuItem key={category.id}>
                    <SidebarMenuButton
                      isActive={isActive}
                      tooltip={category.label}
                      onClick={() => onCategoryChange(category.id)}
                      className="text-[13px]"
                    >
                      {category.icon}
                      <span className="max-lg:hidden">{category.label}</span>
                    </SidebarMenuButton>
                    {category.id === 'detect' && alertCount > 0 && (
                      <SidebarMenuBadge
                        className="top-1.5 font-mono"
                        style={{ color: 'var(--cs-sev-critical-fg)' }}
                      >
                        {alertCount > 999 ? '999+' : alertCount}
                      </SidebarMenuBadge>
                    )}

                    {/* Tabs only render while the rail is expanded — collapsed,
                        the tooltip carries the category and the sub-tab strip in
                        the content column carries the tabs. */}
                    {isActive && !collapsed && (
                      <ul className="mt-0.5 ml-4 flex flex-col gap-px border-l pl-2" style={{ borderColor: 'var(--cs-rule)' }}>
                        {CATEGORY_TABS[category.id].map(tab => (
                          <li key={tab.id}>
                            <button
                              type="button"
                              onClick={() => onTabChange(tab.id)}
                              aria-current={activeTab === tab.id ? 'page' : undefined}
                              className="flex h-6 w-full items-center rounded-md px-2 text-left text-[11px] transition-colors hover:bg-sidebar-accent"
                              style={{ color: activeTab === tab.id ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
                            >
                              {tab.label}
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="p-1.5">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              isActive={docsActive}
              tooltip="Documentation"
              onClick={onOpenDocs}
              className="text-[13px]"
            >
              <BookOpen />
              <span className="max-lg:hidden">Docs</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}

/** Wordmark used in the header; kept next to the rail it aligns with. */
export function Wordmark() {
  return (
    <span className="flex items-center gap-2">
      <span
        className="flex size-6 items-center justify-center rounded-lg"
        style={{ background: 'linear-gradient(135deg, var(--cs-accent), rgba(var(--cs-accent-rgb),0.55))' }}
      >
        <Shield className="size-3.5 text-white" />
      </span>
      <span className="font-display text-[13px] font-bold tracking-tight" style={{ color: 'var(--cs-text-strong)' }}>
        ClaudeSec
      </span>
    </span>
  );
}
