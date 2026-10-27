/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // Semantic design tokens backed by CSS variables (see src/index.css).
      // Values are RGB triplets so Tailwind opacity modifiers (e.g. bg-accent/20) still work.
      colors: {
        app: "rgb(var(--color-bg-app) / <alpha-value>)",
        panel: "rgb(var(--color-bg-panel) / <alpha-value>)",
        elevated: "rgb(var(--color-bg-elevated) / <alpha-value>)",
        surface: "rgb(var(--color-bg-surface) / <alpha-value>)",
        line: "rgb(var(--color-border-subtle) / <alpha-value>)",
        "line-strong": "rgb(var(--color-border-strong) / <alpha-value>)",
        accent: "rgb(var(--color-accent) / <alpha-value>)",
        "accent-soft": "rgb(var(--color-accent-soft) / <alpha-value>)",
        ink: "rgb(var(--color-text-primary) / <alpha-value>)",
        "ink-soft": "rgb(var(--color-text-secondary) / <alpha-value>)",
        "ink-muted": "rgb(var(--color-text-muted) / <alpha-value>)",
        "ink-faint": "rgb(var(--color-text-faint) / <alpha-value>)",
        success: "rgb(var(--color-success) / <alpha-value>)",
        warning: "rgb(var(--color-warning) / <alpha-value>)",
        danger: "rgb(var(--color-error) / <alpha-value>)",
        info: "rgb(var(--color-info) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      borderRadius: {
        card: "0.75rem",
        panel: "1rem",
        pill: "9999px",
      },
      boxShadow: {
        panel: "0 1px 2px 0 rgb(0 0 0 / 0.30)",
        raised: "0 8px 24px -12px rgb(0 0 0 / 0.60)",
        focus: "0 0 0 2px rgb(var(--color-accent) / 0.55)",
      },
      spacing: {
        "grid": "1rem",
        "section": "1.5rem",
      },
      transitionDuration: {
        fast: "150ms",
        base: "200ms",
        slow: "300ms",
      },
    },
  },
  plugins: [],
}
