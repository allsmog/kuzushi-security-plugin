from app import app

@app.route('/orders/<oid>')
def get_order(oid):
    order = Order.objects.get(id=request.GET['id'])
    return order.to_json()
