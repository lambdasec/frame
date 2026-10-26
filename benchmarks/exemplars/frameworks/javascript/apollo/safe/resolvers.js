const { execFile } = require('child_process');
const db = require('./db');

const resolvers = {
  Query: {
    books: async (parent, args, ctx) => {
      return db.query('SELECT * FROM books WHERE author = ?', [args.author]);
    },
    bookByTitle: (_, { title }, { dataSources }) => {
      return dataSources.db.query('SELECT * FROM books WHERE title = ?', [title]);
    },
  },
  Mutation: {
    importBook: async (parent, args) => {
      execFile('book-import', [args.path]);
      return { id: 1 };
    },
  },
};

module.exports = resolvers;
