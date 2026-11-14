import { supabaseAdmin } from '../../lib/admin'

export default async function handler(req, res) {
  await supabaseAdmin.from('invites').insert({ email: req.body.email })
  res.status(200).end()
}
