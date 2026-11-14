import { createClient } from '@/lib/supabase/server'

export async function DELETE(req: Request) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('Unauthorized', { status: 401 })
  const { id } = await req.json()
  await supabase.from('todos').delete().eq('id', id).eq('user_id', user.id)
  return new Response(null, { status: 204 })
}
