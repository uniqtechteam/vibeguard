import Stripe from 'stripe'
import { markPaid } from '@/lib/orders'

export async function POST(req: Request) {
  const event = (await req.json()) as Stripe.Event
  if (event.type === 'checkout.session.completed') {
    await markPaid(event.data.object.id)
  }
  return new Response('ok')
}
