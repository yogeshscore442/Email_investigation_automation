/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          darkest: '#090d16',
          darker: '#0f172a',
          dark: '#1e293b',
          card: '#182234',
          border: '#334155',
          accent: '#38bdf8',
          success: '#22c55e',
          warning: '#eab308',
          danger: '#ef4444',
          critical: '#dc2626'
        }
      }
    },
  },
  plugins: [],
}

