const { render } = require('./tmpl');
function page(req, res) {
  const who = req.query.who;          // source: user input
  return res.send(render(who));       // flows cross-file into tmpl.render
}
module.exports = { page };
