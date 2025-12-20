/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "../frontend/**/*.html",
    "../frontend/js/**/*.js",
    "../frontend/scripts/**/*.js",
    "../frontend/*.js", 
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Kanit', 'sans-serif'],
      },
    },
  },
  plugins: [],
}