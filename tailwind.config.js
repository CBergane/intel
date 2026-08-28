/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./intel/**/*.py",
    "./static/**/*.js"
  ],
  theme: {
    extend: {
      colors: {
        night: "#060b13",
        panel: "#0d1724",
        line: "#203044",
        accent: "#7dd3fc",
        accent2: "#a5f3fc",
        console: {
          canvas: "#060b13",
          sidebar: "#080f19",
          surface: "#0d1724",
          raised: "#111d2c",
          selected: "#142638",
          muted: "#8291a6"
        }
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif"
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Cascadia Code", "Consolas", "monospace"]
      },
      boxShadow: {
        glow: "0 16px 42px rgba(0, 0, 0, 0.18)",
        lift: "0 18px 55px rgba(0, 0, 0, 0.28)"
      },
      maxWidth: {
        "8xl": "90rem",
        "9xl": "100rem"
      }
    },
  },
  plugins: [],
}
