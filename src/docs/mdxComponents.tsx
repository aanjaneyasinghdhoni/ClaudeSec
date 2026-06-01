import React, { createContext, useContext } from 'react';
import { MDXProvider } from '@mdx-js/react';
import { Info as InfoIcon, AlertTriangle, Lightbulb } from 'lucide-react';
import { Mermaid } from './Mermaid';
import { slugifyHeading } from './docsRegistry';

interface DocsNav {
  navigate: (slug: string) => void;
  has: (slug: string) => boolean;
}

const DocsNavContext = createContext<DocsNav>({ navigate: () => {}, has: () => false });

export function DocsNavProvider({ value, children }: { value: DocsNav; children: React.ReactNode }) {
  return <DocsNavContext.Provider value={value}>{children}</DocsNavContext.Provider>;
}

function Callout({ tone, icon, children }: { tone: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="docs-callout" data-tone={tone}>
      <span className="docs-callout-icon">{icon}</span>
      <div className="docs-callout-body">{children}</div>
    </div>
  );
}

type CalloutProps = { children?: React.ReactNode };

const Note = ({ children }: CalloutProps) => (
  <Callout tone="note" icon={<InfoIcon className="w-4 h-4" />}>{children}</Callout>
);
const Info = ({ children }: CalloutProps) => (
  <Callout tone="info" icon={<InfoIcon className="w-4 h-4" />}>{children}</Callout>
);
const Tip = ({ children }: CalloutProps) => (
  <Callout tone="tip" icon={<Lightbulb className="w-4 h-4" />}>{children}</Callout>
);
const Warning = ({ children }: CalloutProps) => (
  <Callout tone="warning" icon={<AlertTriangle className="w-4 h-4" />}>{children}</Callout>
);

type CardProps = { title?: string; href?: string; children?: React.ReactNode };

function useInternalNav() {
  return useContext(DocsNavContext);
}

const Card = ({ title, href, children }: CardProps) => {
  const nav = useInternalNav();
  const internal = typeof href === 'string' && href.startsWith('/');
  const slug = internal ? href!.replace(/^\//, '').split('#')[0] : '';
  return (
    <a
      className="docs-card"
      href={href}
      data-clickable={href ? 'true' : 'false'}
      target={href && !internal ? '_blank' : undefined}
      rel={href && !internal ? 'noopener noreferrer' : undefined}
      onClick={internal && nav.has(slug) ? (e => { e.preventDefault(); nav.navigate(slug); }) : undefined}
    >
      {title && <div className="docs-card-title">{title}</div>}
      <div className="docs-card-body">{children}</div>
    </a>
  );
};

const CardGroup = ({ cols, children }: { cols?: number; children?: React.ReactNode }) => (
  <div className="docs-card-group" style={{ gridTemplateColumns: `repeat(${Number(cols) || 2}, minmax(0,1fr))` }}>
    {children}
  </div>
);

type AnchorProps = React.AnchorHTMLAttributes<HTMLAnchorElement>;

const DocsLink = ({ href, children, ...rest }: AnchorProps) => {
  const nav = useInternalNav();
  if (typeof href === 'string' && href.startsWith('/')) {
    const slug = href.replace(/^\//, '').split('#')[0];
    if (nav.has(slug)) {
      return (
        <a href={href} onClick={e => { e.preventDefault(); nav.navigate(slug); }} {...rest}>
          {children}
        </a>
      );
    }
  }
  const external = typeof href === 'string' && /^https?:\/\//.test(href);
  return (
    <a href={href} target={external ? '_blank' : undefined} rel={external ? 'noopener noreferrer' : undefined} {...rest}>
      {children}
    </a>
  );
};

function headingText(node: React.ReactNode): string {
  if (node == null || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(headingText).join('');
  if (React.isValidElement(node)) {
    return headingText((node.props as { children?: React.ReactNode }).children);
  }
  return '';
}

type HeadingProps = React.HTMLAttributes<HTMLHeadingElement>;

const Heading2 = ({ children, ...rest }: HeadingProps) => (
  <h2 id={slugifyHeading(headingText(children))} {...rest}>{children}</h2>
);
const Heading3 = ({ children, ...rest }: HeadingProps) => (
  <h3 id={slugifyHeading(headingText(children))} {...rest}>{children}</h3>
);

type PreProps = React.HTMLAttributes<HTMLPreElement>;

const Pre = ({ children, ...rest }: PreProps) => {
  if (React.isValidElement(children)) {
    const codeProps = children.props as { className?: string; children?: React.ReactNode };
    if (typeof codeProps.className === 'string' && codeProps.className.includes('language-mermaid')) {
      if (typeof codeProps.children === 'string') {
        return <Mermaid source={codeProps.children} />;
      }
    }
  }
  return <pre {...rest}>{children}</pre>;
};

export const mdxComponents = {
  Note,
  Info,
  Tip,
  Warning,
  Card,
  CardGroup,
  a: DocsLink,
  pre: Pre,
  h2: Heading2,
  h3: Heading3,
};

export function DocsMDX({ children }: { children: React.ReactNode }) {
  return <MDXProvider components={mdxComponents}>{children}</MDXProvider>;
}
