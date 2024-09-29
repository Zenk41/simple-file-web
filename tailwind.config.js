/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./views/**/*.{html,templ,go}", "./node_modules/flowbite/**/*.js"],
  theme: {
    extend: {},
  },
  plugins: [require("flowbite/plugin")],
};
