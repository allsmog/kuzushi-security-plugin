function render(name) {
  // BUG: untrusted name interpolated into HTML in another file → XSS sink
  return `<h1>Hello ${name}</h1>`;
}
module.exports = { render };
