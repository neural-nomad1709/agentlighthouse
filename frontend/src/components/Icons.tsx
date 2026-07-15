// Inline SVG icons — no emoji, no external assets.

export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg className="mark" width={size} height={size} viewBox="0 0 24 24" fill="none"
      aria-hidden="true">
      <defs>
        <linearGradient id="alg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#5ac8fa" />
          <stop offset="1" stopColor="#7aa2ff" />
        </linearGradient>
      </defs>
      {/* a shield with a beam — governance + evidence, no wordmark */}
      <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"
        fill="url(#alg)" opacity="0.16" stroke="url(#alg)" strokeWidth="1.4" />
      <path d="M12 7v10M8 12l4-3 4 3" stroke="url(#alg)" strokeWidth="1.6"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Search({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.8" />
      <path d="M21 21l-4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  )
}

export function Check({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.2"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Cross({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2.2"
        strokeLinecap="round" />
    </svg>
  )
}

export function Theme({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"
        stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
    </svg>
  )
}
