const db = require('../database/db-config');

module.exports = {
  getAll,
  findById,
  findBy,
  addUser,
};

function getAll() {
  return db('users');
}

function findById(id) {
  return db('users').where({id}).first();
}

function findBy(filter) {
  return db('users').where(filter);
}

async function addUser(user) {
  const [id] = await db('users').insert(user);
  return findById(id);
}