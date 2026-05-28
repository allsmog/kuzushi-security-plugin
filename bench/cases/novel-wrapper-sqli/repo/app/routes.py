from app import app, request, dao

@app.route('/report')
def report():
    name = request.args['name']
    # BUG: untrusted name concatenated into SQL, run via a custom wrapper (dao.run)
    return dao.run("SELECT * FROM reports WHERE owner = '" + name + "'")
