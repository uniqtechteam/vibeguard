import { db } from '@/lib/db'

export async function POST(req: Request) {
  await db.setting.update({ where: { id: 1 }, data: await req.json() })
  return new Response('ok')
}
