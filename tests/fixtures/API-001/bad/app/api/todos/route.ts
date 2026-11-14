import { db } from '@/lib/db'

export async function GET() {
  return Response.json(await db.todo.findMany())
}

export async function DELETE(req: Request) {
  const { id } = await req.json()
  await db.todo.delete({ where: { id } })
  return new Response(null, { status: 204 })
}
