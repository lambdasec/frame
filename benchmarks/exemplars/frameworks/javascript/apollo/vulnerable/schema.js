module.exports = `#graphql
  type Book { id: ID!, title: String, author: String }
  type Query {
    books(author: String): [Book]
    bookByTitle(title: String!): Book
    report(name: String!): String
  }
  type Mutation {
    importBook(path: String!): Book
  }
`;
