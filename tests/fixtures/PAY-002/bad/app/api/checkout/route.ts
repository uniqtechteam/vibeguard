import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const { amount, name } = await req.json()
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      quantity: 1,
      price_data: { currency: 'usd', unit_amount: Number(amount) * 100, product_data: { name } },
    }],
    success_url: 'https://example.com/thanks',
  })
  return Response.json({ url: session.url })
}
