import * as React from "react"

const MOBILE_BREAKPOINT = 768

/**
 * True below `mobileBreakpoint`. The default matches shadcn's own 768px, but
 * the shell passes 1024: below that width there is no room for an icon rail and
 * a list column side by side, so both have to collapse into the same off-canvas
 * sheet rather than the sheet appearing only on phones.
 */
export function useIsMobile(mobileBreakpoint: number = MOBILE_BREAKPOINT) {
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined)

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${mobileBreakpoint - 1}px)`)
    const onChange = () => {
      setIsMobile(window.innerWidth < mobileBreakpoint)
    }
    mql.addEventListener("change", onChange)
    setIsMobile(window.innerWidth < mobileBreakpoint)
    return () => mql.removeEventListener("change", onChange)
  }, [mobileBreakpoint])

  return !!isMobile
}
