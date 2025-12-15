/** @type {import('tailwindcss').Config} */
module.exports = {
  // ✅ ระบุเฉพาะไฟล์ HTML และ JS ใน frontend เท่านั้น
  // ❌ ห้ามใส่ .css ลงในนี้เด็ดขาด (เดี๋ยวเกิดลูปนรก)
  // ❌ ห้ามใส่ ./ (current directory) เพราะมันจะไปกวาด node_modules ใน backend
  content: [
    "../frontend/**/*.html",
    "../frontend/**/*.js"
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