const store = new Map();

module.exports = {
  get(key, compute) {
    if (!store.has(key)) store.set(key, compute(key));
    return store.get(key);
  },
};
