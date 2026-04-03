import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  console.log('Seeding database...')

  const apiKey = await prisma.apiKey.create({
    data: {
      key: 'SOLSTICE-DEV-API-KEY-12345',
      active: true
    }
  })

  const license = await prisma.license.create({
    data: {
      code: 'SOLSTICE-A1B2-C3D4-E5F6',
      active: true,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
    }
  })

  const studentEmail = await prisma.studentEmail.create({
    data: {
      email: 'student@university.edu',
      active: true
    }
  })

  console.log('Database seeded successfully!')
  console.log('API Key:', apiKey.key)
  console.log('License:', license.code)
  console.log('Student Email:', studentEmail.email)
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
