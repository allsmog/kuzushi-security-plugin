from app import app

@app.route('/checkout', methods=['POST'])
def checkout(request):
    amount = request.json['amount']
    charge(request.user.card, amount)
    order.status = 'paid'
    balance -= amount
    return {'ok': True}
