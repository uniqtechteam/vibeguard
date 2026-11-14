import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
const PRICES: Record<string, { amount: number }> = { pro: { amount: 2000 } }

export async function POST(req: Request) {
  const { plan } = await req.json()
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      quantity: 1,
      price_data: { currency: 'usd', unit_amount: PRICES[plan].amount, product_data: { name: plan } },
    }],
    success_url: 'https://example.com/thanks',
  })
  return Response.json({ url: session.url })
}
