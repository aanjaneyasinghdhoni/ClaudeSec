import React, { useEffect, useId, useRef, useState } from 'react';

function currentTheme(): 'dark' | 'default' {
  if (typeof document === 'undefined') return 'dark';
  return document.documentElement.classList.contains('light') ? 'default' : 'dark';
}

export function Mermaid({ source }: { source: string }) {
  const rawId = useId();
  const renderId = useRef('mermaid-' + rawId.replace(/[^a-zA-Z0-9]/g, ''));
  const [svg, setSvg] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'default'>(() => currentTheme());

  useEffect(() => {
    const el = document.documentElement;
    const observer = new MutationObserver(() => {
      const next = currentTheme();
      setTheme(prev => (prev === next ? prev : next));
    });
    observer.observe(el, { attributes: true, attributeFilter: ['data-theme', 'class'] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let cancelled = false;
    setFailed(false);
    (async () => {
      try {
        const mermaid = (await import('mermaid')).default;
        mermaid.initialize({ startOnLoad: false, theme });
        const { svg: rendered } = await mermaid.render(renderId.current, source);
        if (!cancelled) setSvg(rendered);
      } catch {
        if (!cancelled) {
          setSvg(null);
          setFailed(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [source, theme]);

  if (failed) {
    return (
      <pre>
        <code>{source}</code>
      </pre>
    );
  }

  if (svg === null) {
    return <div className="docs-mermaid" aria-busy="true" />;
  }

  return <div className="docs-mermaid" dangerouslySetInnerHTML={{ __html: svg }} />;
}
