import { authHandler } from '@/lib/auth'

export async function POST(request: Request) {
  return authHandler(request)
}
