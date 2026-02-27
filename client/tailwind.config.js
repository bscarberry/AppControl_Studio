/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Cascadia Code'", "'Fira Code'", "ui-monospace", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      colors: {
        // Neutral dark theme optimized for dense technical content
        surface: {
          0: "#0d0d0d",
          1: "#141414",
          2: "#1c1c1c",
          3: "#242424",
          4: "#2e2e2e",
          5: "#3a3a3a",
        },
        border: {
          DEFAULT: "#2e2e2e",
          muted: "#242424",
          strong: "#404040",
        },
        text: {
          primary: "#e8e8e8",
          secondary: "#a0a0a0",
          muted: "#606060",
          inverse: "#0d0d0d",
        },
        accent: {
          blue: "#3b82f6",
          "blue-dim": "#1d4ed8",
          green: "#22c55e",
          "green-dim": "#166534",
          red: "#ef4444",
          "red-dim": "#991b1b",
          yellow: "#eab308",
          "yellow-dim": "#854d0e",
          orange: "#f97316",
          "orange-dim": "#9a3412",
          purple: "#a855f7",
        },
      },
    },
  },
  plugins: [],
};
