import Stripe from 'stripe'
import { markPaid } from '@/lib/orders'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const body = await req.text()
  const signature = req.headers.get('stripe-signature')!
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!)
  switch (event.type) {
    case 'checkout.session.completed':
      await markPaid(event.data.object.id)
  }
  return new Response('ok')
}
