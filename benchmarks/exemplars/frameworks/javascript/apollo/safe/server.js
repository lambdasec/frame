const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const typeDefs = require('./schema');
const resolvers = require('./resolvers');
const { reporting } = require('./pools');

const server = new ApolloServer({ typeDefs, resolvers });
// The context object is every resolver's third argument: the reporting pool, and the tenant the
// client names in a header.
startStandaloneServer(server, {
  listen: { port: 4000 },
  context: async ({ req }) => ({ reports: reporting, tenant: req.headers['x-tenant'] }),
});
