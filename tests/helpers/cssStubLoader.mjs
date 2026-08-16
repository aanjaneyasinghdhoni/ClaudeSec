// A minimal Node ESM loader hook that stubs out CSS imports.
//
// The frontend components under test (WebhookDeliverySection.tsx,
// ComparePanel.tsx) pull in `src/components/data`, which statically imports
// `data-table.css`. That's fine under Vite, but this test suite runs plain
// `tsx` against Node directly — Node has no idea what a `.css` file is and
// throws ERR_UNKNOWN_FILE_EXTENSION. This hook intercepts any `.css`
// specifier and hands back an empty module instead of touching disk, so a
// component file can be imported for its pure exports (formatters, small
// helpers) without a real DOM or a bundler.
export async function load(url, context, nextLoad) {
  if (url.endsWith('.css')) {
    return { format: 'module', source: 'export default {};', shortCircuit: true };
  }
  return nextLoad(url, context);
}
