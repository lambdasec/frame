// The Prisma Client singleton (prisma.io/docs: "Instantiating Prisma Client").
const { PrismaClient } = require('@prisma/client');

module.exports = new PrismaClient();
