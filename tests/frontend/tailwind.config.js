/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050816",
          card: "rgba(255, 255, 255, 0.03)",
          border: "rgba(255, 255, 255, 0.08)",
          blue: "#00bfff",
          blueGlow: "rgba(0, 191, 255, 0.2)",
          success: "#10b981",
          danger: "#ef4444",
          warning: "#f59e0b",
          gray: "#94a3b8",
          text: "#f8fafc"
        }
      },
      fontFamily: {
        sans: ["Outfit", "Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"]
      },
      animation: {
        "grid-move": "gridMove 20s linear infinite",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
      keyframes: {
        gridMove: {
          "0%": { transform: "translateY(0)" },
          "100%": { transform: "translateY(50px)" }
        }
      }
    },
  },
  plugins: [],
}
