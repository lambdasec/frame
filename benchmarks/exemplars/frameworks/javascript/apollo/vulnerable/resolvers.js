const { exec } = require('child_process');
const db = require('./db');
const { reporting } = require('./pools');

const resolvers = {
  Query: {
    books: async (parent, args, ctx) => {
      return db.query("SELECT * FROM books WHERE author = '" + args.author + "'");  // frame-expect: CWE-89
    },
    bookByTitle: (_, { title }) => {
      return reporting.query("SELECT * FROM books WHERE title = '" + title + "'");  // frame-expect: CWE-89
    },
  },
  Mutation: {
    importBook: async (parent, args) => {
      exec('book-import ' + args.path);  // frame-expect: CWE-78
      return { id: 1 };
    },
  },
};

module.exports = resolvers;
