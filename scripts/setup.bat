@echo off
echo Setting up Solstice Proxy Detection System...

echo Installing dependencies...
npm install

echo Installing Prisma CLI...
npm install -g prisma

echo Generating Prisma client...
npx prisma generate

echo Creating database migration...
npx prisma migrate dev --name init

echo Seeding database...
npx prisma db seed

echo Setup complete!
echo To start the server: npm run dev
